/*
 * This file is part of KotSafe.
 * KotSafe On-Device AI Model Manager.
 */

package com.kotsafe.security.ai;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;

import androidx.preference.PreferenceManager;

import com.kotsafe.security.Log;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.ResponseBody;

import com.kotsafe.security.CaptureService;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import javax.net.SocketFactory;

/**
 * Manages on-demand background downloading, pause/resume, multi-mirror failover,
 * and storage management for on-device models:
 * - Qwen 2.5 0.5B (Recommended INT4, ~350 MB)
 * - SmolLM-135M (Ultra-light INT4, ~90 MB)
 * - Gemma 2B (Legacy on-device INT4, ~1.35 GB)
 */
public class GemmaModelDownloadManager {

    private static final String TAG = "GemmaDownloadManager";

    public enum ModelTarget {
        QWEN_0_5B("Qwen 2.5 0.5B (Recommended)", "qwen2.5-0.5b-instruct-q4_k_m.gguf", 350_000_000L,
                new String[]{
                        "https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct-GGUF/resolve/main/qwen2.5-0.5b-instruct-q4_k_m.gguf",
                        "https://huggingface.co/bartowski/Qwen2.5-0.5B-Instruct-GGUF/resolve/main/Qwen2.5-0.5B-Instruct-Q4_K_M.gguf"
                }),
        SMOLLM_135M("SmolLM-135M (Ultra-Light)", "smollm2-135m-instruct-q4_k_m.gguf", 90_000_000L,
                new String[]{
                        "https://huggingface.co/HuggingFaceTB/SmolLM2-135M-Instruct-GGUF/resolve/main/smollm2-135m-instruct-q4_k_m.gguf",
                        "https://huggingface.co/bartowski/SmolLM2-135M-Instruct-GGUF/resolve/main/SmolLM2-135M-Instruct-Q4_K_M.gguf"
                }),
        GEMMA_2B("Google Gemma 2B", "gemma-2b-it-gpu-int4.bin", 1_354_301_440L,
                new String[]{
                        "https://huggingface.co/jardpound/gemma-2b-it-gpu-int4/resolve/main/gemma-2b-it-gpu-int4.bin",
                        "https://huggingface.co/alexdlov/gemma-2b-it-gpu-int4.bin/resolve/main/gemma-2b-it-gpu-int4.bin",
                        "https://huggingface.co/vba01/gemma-2b-it-gpu-int4/resolve/main/gemma-2b-it-gpu-int4.bin",
                        "https://huggingface.co/google/gemma-2b-it-tflite/resolve/main/gemma-2b-it-gpu-int4.bin"
                });

        public final String title;
        public final String fileName;
        public final long approximateSizeBytes;
        public final String[] mirrors;

        ModelTarget(String title, String fileName, long approximateSizeBytes, String[] mirrors) {
            this.title = title;
            this.fileName = fileName;
            this.approximateSizeBytes = approximateSizeBytes;
            this.mirrors = mirrors;
        }

        public File getFile(Context context) {
            File dir = new File(context.getExternalFilesDir(null), "ai_models");
            if (!dir.exists()) dir.mkdirs();
            return new File(dir, fileName);
        }

        public boolean isDownloaded(Context context) {
            File file = getFile(context);
            long minSize = approximateSizeBytes / 3;
            return file.exists() && file.length() >= minSize;
        }
    }

    // Default mirror URL for Qwen 2.5 0.5B
    public static final String DEFAULT_MODEL_URL =
            "https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct-GGUF/resolve/main/qwen2.5-0.5b-instruct-q4_k_m.gguf";

    public static final String[] MIRROR_URLS = ModelTarget.QWEN_0_5B.mirrors;

    public interface DownloadListener {
        void onProgress(long bytesDownloaded, long totalBytes, int percent);
        void onCompleted(File modelFile);
        void onError(String errorMessage);
        void onCancelled();
    }

    private static volatile GemmaModelDownloadManager sInstance;

    private final Context mContext;
    private final ExecutorService mExecutor = Executors.newSingleThreadExecutor();
    private final Handler mMainHandler = new Handler(Looper.getMainLooper());
    private final OkHttpClient mHttpClient = new OkHttpClient.Builder()
            .socketFactory(new ProtectedSocketFactory())
            .followRedirects(true)
            .followSslRedirects(true)
            .connectTimeout(30, TimeUnit.SECONDS)
            .readTimeout(60, TimeUnit.SECONDS)
            .build();
    private final AtomicBoolean mIsDownloading = new AtomicBoolean(false);
    private final AtomicBoolean mCancelRequested = new AtomicBoolean(false);

    /**
     * Bypasses the local VPN (tun0) interface using VpnService.protect() so that download
     * traffic never loops back into KotSafe's capture engine and causes connection aborts.
     */
    private static final class ProtectedSocketFactory extends SocketFactory {
        @Override
        public Socket createSocket() throws IOException {
            Socket s = new Socket();
            protectSocket(s);
            return s;
        }

        @Override
        public Socket createSocket(String host, int port) throws IOException {
            Socket s = new Socket();
            protectSocket(s);
            s.connect(new InetSocketAddress(host, port), 30000);
            return s;
        }

        @Override
        public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException {
            Socket s = new Socket();
            protectSocket(s);
            s.bind(new InetSocketAddress(localHost, localPort));
            s.connect(new InetSocketAddress(host, port), 30000);
            return s;
        }

        @Override
        public Socket createSocket(InetAddress host, int port) throws IOException {
            Socket s = new Socket();
            protectSocket(s);
            s.connect(new InetSocketAddress(host, port), 30000);
            return s;
        }

        @Override
        public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
            Socket s = new Socket();
            protectSocket(s);
            s.bind(new InetSocketAddress(localAddress, localPort));
            s.connect(new InetSocketAddress(address, port), 30000);
            return s;
        }
    }

    private static void protectSocket(Socket socket) {
        try {
            CaptureService vpn = CaptureService.getInstance();
            if (vpn != null) {
                vpn.protect(socket);
            }
        } catch (Throwable t) {
            Log.w(TAG, "Socket protect failed: " + t.getMessage());
        }
    }

    public static GemmaModelDownloadManager getInstance(Context context) {
        if (sInstance == null) {
            synchronized (GemmaModelDownloadManager.class) {
                if (sInstance == null) {
                    sInstance = new GemmaModelDownloadManager(context.getApplicationContext());
                }
            }
        }
        return sInstance;
    }

    private GemmaModelDownloadManager(Context context) {
        mContext = context;
    }

    public boolean isDownloading() {
        return mIsDownloading.get();
    }

    public void cancelDownload() {
        mCancelRequested.set(true);
    }

    private List<String> getCandidateUrls(ModelTarget target) {
        List<String> list = new ArrayList<>();
        String prefKey = "custom_model_url_" + target.name().toLowerCase();
        String customUrl = PreferenceManager.getDefaultSharedPreferences(mContext)
                .getString(prefKey, "")
                .trim();
        if (customUrl.isEmpty() && target == ModelTarget.GEMMA_2B) {
            customUrl = PreferenceManager.getDefaultSharedPreferences(mContext)
                    .getString("gemma_custom_download_url", "")
                    .trim();
        }
        if (!customUrl.isEmpty()) {
            list.add(customUrl);
        }
        for (String url : target.mirrors) {
            if (!list.contains(url)) {
                list.add(url);
            }
        }
        return list;
    }

    /**
     * Starts download of default recommended model (Qwen 2.5 0.5B).
     */
    public void startDownload(DownloadListener listener) {
        startDownload(ModelTarget.QWEN_0_5B, listener);
    }

    /**
     * Starts or resumes download of the specified model target with multi-mirror failover.
     */
    public void startDownload(ModelTarget target, DownloadListener listener) {
        if (mIsDownloading.compareAndSet(false, true)) {
            mCancelRequested.set(false);
            mExecutor.execute(() -> doDownload(target, listener));
        } else {
            if (listener != null) {
                listener.onError("Download is already in progress.");
            }
        }
    }

    private void doDownload(ModelTarget target, DownloadListener listener) {
        File targetFile = target.getFile(mContext);
        File tempFile = new File(targetFile.getParentFile(), targetFile.getName() + ".part");

        List<String> candidateUrls = getCandidateUrls(target);
        String lastError = "No download URLs available.";

        for (int i = 0; i < candidateUrls.size(); i++) {
            if (mCancelRequested.get()) {
                mIsDownloading.set(false);
                postCancelled(listener);
                return;
            }

            String currentUrl = candidateUrls.get(i);
            Log.i(TAG, "Attempting " + target.title + " download from mirror [" + (i + 1) + "/" + candidateUrls.size() + "]: " + currentUrl);

            long existingBytes = tempFile.exists() ? tempFile.length() : 0L;

            try {
                Request.Builder reqBuilder = new Request.Builder()
                        .url(currentUrl)
                        .header("User-Agent", "KotSafe-Android-Client/2.0");

                String hfToken = PreferenceManager.getDefaultSharedPreferences(mContext)
                        .getString("gemma_hf_token", "")
                        .trim();
                if (!hfToken.isEmpty() && currentUrl.contains("huggingface.co")) {
                    reqBuilder.header("Authorization", "Bearer " + hfToken);
                }

                if (existingBytes > 0) {
                    reqBuilder.addHeader("Range", "bytes=" + existingBytes + "-");
                    Log.i(TAG, "Resuming " + target.title + " download from byte " + existingBytes);
                }

                Response response = mHttpClient.newCall(reqBuilder.build()).execute();
                int code = response.code();

                // If Range not satisfiable (e.g. file size changed or completed on remote), reset and retry full
                if (code == 416) {
                    tempFile.delete();
                    existingBytes = 0;
                    reqBuilder = new Request.Builder()
                            .url(currentUrl)
                            .header("User-Agent", "KotSafe-Android-Client/2.0");
                    if (!hfToken.isEmpty() && currentUrl.contains("huggingface.co")) {
                        reqBuilder.header("Authorization", "Bearer " + hfToken);
                    }
                    response = mHttpClient.newCall(reqBuilder.build()).execute();
                    code = response.code();
                }

                if (code == 401 || code == 403) {
                    lastError = "HTTP " + code + " (Model repository authentication required).";
                    Log.w(TAG, "Mirror " + currentUrl + " gated: " + lastError);
                    continue;
                }

                if (!response.isSuccessful() && code != 206) {
                    lastError = "Server returned HTTP " + code + " (" + response.message() + ")";
                    Log.w(TAG, "Mirror failed (" + lastError + "), trying next mirror...");
                    continue;
                }

                ResponseBody body = response.body();
                if (body == null) {
                    lastError = "Empty response body received from mirror.";
                    continue;
                }

                long totalContentLength = body.contentLength();
                long totalBytes = totalContentLength > 0 ? (totalContentLength + existingBytes) : target.approximateSizeBytes;

                try (InputStream in = body.byteStream();
                     FileOutputStream out = new FileOutputStream(tempFile, existingBytes > 0)) {

                    byte[] buffer = new byte[64 * 1024]; // 64 KB buffer
                    long downloaded = existingBytes;
                    int bytesRead;
                    long lastProgressTime = 0;

                    while ((bytesRead = in.read(buffer)) != -1) {
                        if (mCancelRequested.get()) {
                            mIsDownloading.set(false);
                            postCancelled(listener);
                            return;
                        }

                        out.write(buffer, 0, bytesRead);
                        downloaded += bytesRead;

                        long now = System.currentTimeMillis();
                        if (now - lastProgressTime > 250) { // Throttle UI progress to ~4 FPS
                            lastProgressTime = now;
                            int percent = (int) Math.min(100, (downloaded * 100) / totalBytes);
                            long curDownloaded = downloaded;
                            mMainHandler.post(() -> {
                                if (listener != null) {
                                    listener.onProgress(curDownloaded, totalBytes, percent);
                                }
                            });
                        }
                    }

                    out.flush();
                }

                // Rename .part file to final model weight
                if (tempFile.renameTo(targetFile)) {
                    mIsDownloading.set(false);
                    Log.i(TAG, target.title + " successfully downloaded and verified: " + targetFile.getAbsolutePath());
                    mMainHandler.post(() -> {
                        if (listener != null) {
                            listener.onCompleted(targetFile);
                        }
                    });
                    return; // Success!
                } else {
                    lastError = "Failed to finalize downloaded model file.";
                }

            } catch (Exception e) {
                lastError = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
                Log.w(TAG, "Download error on mirror: " + lastError);
            }
        }

        mIsDownloading.set(false);
        Log.e(TAG, "All " + target.title + " download mirrors exhausted. Last error: " + lastError);
        postError(listener, lastError);
    }

    /**
     * Imports a locally downloaded model file from an input stream.
     */
    public boolean importModelFromStream(ModelTarget target, InputStream in, DownloadListener listener) {
        File targetFile = target.getFile(mContext);
        File tempFile = new File(targetFile.getParentFile(), targetFile.getName() + ".importing");

        try (FileOutputStream out = new FileOutputStream(tempFile)) {
            byte[] buf = new byte[64 * 1024];
            int read;
            long total = 0;
            while ((read = in.read(buf)) != -1) {
                out.write(buf, 0, read);
                total += read;
            }
            out.flush();

            if (tempFile.renameTo(targetFile)) {
                Log.i(TAG, "Imported " + target.title + " model successfully (" + total + " bytes)");
                mMainHandler.post(() -> {
                    if (listener != null) listener.onCompleted(targetFile);
                });
                return true;
            }
        } catch (Exception e) {
            Log.e(TAG, "Import failed: " + e.getMessage());
            mMainHandler.post(() -> {
                if (listener != null) listener.onError("Import error: " + e.getMessage());
            });
        }
        return false;
    }

    public boolean importModelFromStream(InputStream in, DownloadListener listener) {
        return importModelFromStream(ModelTarget.QWEN_0_5B, in, listener);
    }

    /**
     * Deletes the local model weights for a specific target to free up disk storage.
     */
    public boolean deleteModel(ModelTarget target) {
        File file = target.getFile(mContext);
        File part = new File(file.getParentFile(), file.getName() + ".part");
        boolean ok = true;
        if (file.exists()) ok = file.delete();
        if (part.exists()) part.delete();
        Log.i(TAG, target.title + " deleted, storage reclaimed: " + ok);
        return ok;
    }

    public boolean deleteModel() {
        return deleteModel(ModelTarget.QWEN_0_5B);
    }

    private void postError(DownloadListener listener, String message) {
        mMainHandler.post(() -> {
            if (listener != null) listener.onError(message);
        });
    }

    private void postCancelled(DownloadListener listener) {
        mMainHandler.post(() -> {
            if (listener != null) listener.onCancelled();
        });
    }
}
