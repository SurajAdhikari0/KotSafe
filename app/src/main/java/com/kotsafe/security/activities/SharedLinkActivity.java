package com.kotsafe.security.activities;

import android.content.Intent;
import android.os.Bundle;
import androidx.appcompat.app.AlertDialog;
import com.kotsafe.security.R;
import com.kotsafe.security.model.SharedLinkCheck;
import java.io.IOException;
import java.net.URI;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class SharedLinkActivity extends BaseActivity {
    private final ExecutorService worker = Executors.newSingleThreadExecutor();

    @Override protected void onCreate(Bundle saved) {
        super.onCreate(saved);
        AlertDialog dialog = new AlertDialog.Builder(this)
                .setTitle(R.string.shared_link_title)
                .setMessage(R.string.shared_link_loading)
                .setPositiveButton(android.R.string.ok, (d, which) -> finish())
                .setOnCancelListener(d -> finish()).show();
        String url;
        try {
            Intent intent = getIntent();
            if (!Intent.ACTION_SEND.equals(intent.getAction()) || !"text/plain".equals(intent.getType()))
                throw new IOException();
            url = SharedLinkCheck.extract(intent.getCharSequenceExtra(Intent.EXTRA_TEXT));
        } catch (IOException | RuntimeException invalid) {
            dialog.setMessage(getString(R.string.shared_link_invalid));
            return;
        }
        dialog.setTitle(URI.create(url).getHost());
        worker.execute(() -> {
            SharedLinkCheck.Result result;
            try {
                result = SharedLinkCheck.check(getApplicationContext(), url);
            } catch (IOException | RuntimeException unavailable) {
                result = SharedLinkCheck.Result.UNAVAILABLE;
            }
            int message = result == SharedLinkCheck.Result.MATCH ? R.string.shared_link_match :
                    result == SharedLinkCheck.Result.UNKNOWN ? R.string.shared_link_unknown : R.string.shared_link_unavailable;
            runOnUiThread(() -> {
                if (!isFinishing() && !isDestroyed()) dialog.setMessage(getString(message));
            });
        });
    }

    @Override protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        recreate();
    }

    @Override protected void onDestroy() {
        worker.shutdownNow();
        super.onDestroy();
    }
}
