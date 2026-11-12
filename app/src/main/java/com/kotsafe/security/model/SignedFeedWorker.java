package com.kotsafe.security.model;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;
import androidx.annotation.NonNull;
import androidx.work.Constraints;
import androidx.work.ExistingPeriodicWorkPolicy;
import androidx.work.NetworkType;
import androidx.work.PeriodicWorkRequest;
import androidx.work.OneTimeWorkRequest;
import androidx.work.ExistingWorkPolicy;
import androidx.work.Worker;
import androidx.work.WorkerParameters;
import androidx.work.WorkManager;
import androidx.work.Data;
import com.google.android.gms.tasks.Tasks;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseUser;
import com.kotsafe.security.BuildConfig;
import com.kotsafe.security.p2p.P2PLicenseManager;
import org.json.JSONObject;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.HttpsURLConnection;

public final class SignedFeedWorker extends Worker {
    public static final String WORK = "KotSafeSignedAndroidFeed";
    private static final String ROOT = "https://kotsafe.com/api/v1/intel/android/";
    private static final String SCOPE = "kotsafe-android-public";

    public SignedFeedWorker(@NonNull Context context, @NonNull WorkerParameters params) {
        super(context, params);
    }

    public static SharedPreferences state(Context context) {
        return context.getSharedPreferences(WORK, Context.MODE_PRIVATE);
    }

    public static String account() {
        try {
            FirebaseUser user = FirebaseAuth.getInstance().getCurrentUser();
            return user == null ? "" : user.getUid();
        } catch (IllegalStateException unavailable) {
            return "";
        }
    }

    public static boolean enabled(Context context) {
        String uid = account();
        return !uid.isEmpty() && uid.equals(state(context).getString("owner", ""));
    }

    public static synchronized void configure(Context context, boolean enable) {
        String uid = account();
        WorkManager manager = WorkManager.getInstance(context);
        if (!enable || uid.isEmpty()) {
            state(context).edit().clear().apply();
            manager.cancelUniqueWork(WORK);
            manager.cancelUniqueWork(WORK+"Now");
            return;
        }
        String generation = UUID.randomUUID().toString();
        state(context).edit().clear().putString("owner", uid).putString("generation", generation).apply();
        Constraints constraints = new Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build();
        PeriodicWorkRequest request = new PeriodicWorkRequest.Builder(SignedFeedWorker.class, 30, TimeUnit.MINUTES)
                .setInputData(new Data.Builder().putString("generation", generation).build())
                .setConstraints(constraints).build();
        manager.enqueueUniquePeriodicWork(WORK, ExistingPeriodicWorkPolicy.REPLACE, request);
    }

    public static void refreshNow(Context context) {
        if (!enabled(context)) return;
        String generation = state(context).getString("generation", "");
        OneTimeWorkRequest request = new OneTimeWorkRequest.Builder(SignedFeedWorker.class)
                .setInputData(new Data.Builder().putString("generation",generation).build())
                .setConstraints(new Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build()).build();
        WorkManager.getInstance(context).enqueueUniqueWork(WORK+"Now", ExistingWorkPolicy.KEEP, request);
    }

    static IntelligenceSnapshotStore store(Context context, String uid) throws IOException {
            IntelligenceManifestV2Verifier verifier = new IntelligenceManifestV2Verifier(Collections.singletonMap(
                    BuildConfig.ANDROID_FEED_KEY_ID, Base64.decode(BuildConfig.ANDROID_FEED_PIN, Base64.DEFAULT)), SCOPE);
            String folder = UUID.nameUUIDFromBytes(uid.getBytes(StandardCharsets.UTF_8)).toString();
            return new IntelligenceSnapshotStore(new File(context.getNoBackupFilesDir(), "signed-feed/"+folder), verifier);
    }

    private boolean current() {
        return !isStopped() && enabled(getApplicationContext())
                && state(getApplicationContext()).getString("generation","").equals(getInputData().getString("generation"));
    }

    @NonNull @Override public Result doWork() {
        Context context = getApplicationContext();
        try {
            if (BuildConfig.ANDROID_FEED_PIN.isEmpty() || !current()) return Result.success();
            FirebaseUser user = FirebaseAuth.getInstance().getCurrentUser();
            if (user == null || !user.getUid().equals(state(context).getString("owner",""))) return Result.success();
            String device = P2PLicenseManager.getInstance(context).getOrCreateDeviceId();
            String access = Tasks.await(user.getIdToken(false), 15, TimeUnit.SECONDS).getToken();
            String ticket = enroll(device, access);
            IntelligenceSnapshotStore store = store(context,user.getUid());
            IntelligenceV2SyncCoordinator sync = new IntelligenceV2SyncCoordinator(store, store.verifier(),
                    Collections.singleton("kotsafe.com"), new IntelligenceV2SyncCoordinator.HttpsFetcher());
            IntelligenceV2SyncCoordinator.DeviceCredential credential = new IntelligenceV2SyncCoordinator.DeviceCredential() {
                public String tenantScope() { return SCOPE; }
                public String deviceId() { return device; }
                public String bearerToken() { return ticket; }
            };
            if (!current()) return Result.success();
            IntelligenceManifestV2Verifier.Snapshot snapshot = sync.sync(true, URI.create(ROOT+"manifest"), credential, System.currentTimeMillis()/1000);
            synchronized (SignedFeedWorker.class) {
                if (current()) state(context).edit().putLong("verified", System.currentTimeMillis())
                        .putLong("version",snapshot.version).putLong("expiry",snapshot.expiresAt*1000).remove("error").apply();
            }
            return Result.success();
        } catch (Exception failure) {
            synchronized (SignedFeedWorker.class) {
                if (!current()) return Result.success();
                state(context).edit().putString("error", failure instanceof EnrollmentFailure
                        ? failure.getMessage() : "Update unavailable or verification failed.").apply();
            }
            return getRunAttemptCount() < 2 ? Result.retry() : Result.success();
        }
    }

    private static final class EnrollmentFailure extends IOException {
        EnrollmentFailure(int status) { super("Device enrollment returned HTTP "+status+"."); }
    }

    private static String enroll(String device, String access) throws Exception {
        if (access == null || access.isEmpty()) throw new IOException("Sign-in required");
        HttpsURLConnection connection = (HttpsURLConnection)new URL(ROOT+"enroll").openConnection();
        try {
            connection.setInstanceFollowRedirects(false);
            connection.setRequestMethod("POST");
            connection.setConnectTimeout(8000);
            connection.setReadTimeout(10000);
            connection.setRequestProperty("Accept","application/json");
            connection.setRequestProperty("Authorization","Bearer "+access);
            connection.setRequestProperty("X-KotSafe-Device-Id",device);
            int status = connection.getResponseCode();
            if (status != 200) throw new EnrollmentFailure(status);
            try (InputStream input = connection.getInputStream()) {
                java.io.ByteArrayOutputStream bytes = new java.io.ByteArrayOutputStream();
                byte[] buffer = new byte[512];
                int count;
                while ((count=input.read(buffer)) != -1) {
                    if (bytes.size()+count > 2048) throw new IOException("Invalid enrollment response");
                    bytes.write(buffer,0,count);
                }
                String token = new JSONObject(bytes.toString("UTF-8")).getString("token");
                if (!token.matches("[a-f0-9]{64}")) throw new IOException("Invalid enrollment response");
                return token;
            }
        } finally { connection.disconnect(); }
    }
}
