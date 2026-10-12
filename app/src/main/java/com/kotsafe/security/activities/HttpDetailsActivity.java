/*
 * This file is part of KotSafe.
 *
 * KotSafe is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * KotSafe is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with KotSafe.  If not, see <http://www.gnu.org/licenses/>.
 * * Copyright 2026 - KotSafe Cyber Security Project
 */

package com.kotsafe.security.activities;

import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;

import androidx.activity.result.ActivityResult;
import androidx.appcompat.app.AlertDialog;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.NonNull;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentActivity;
import androidx.viewpager2.adapter.FragmentStateAdapter;
import androidx.viewpager2.widget.ViewPager2;

import com.kotsafe.security.CaptureService;
import com.kotsafe.security.ConnectionsRegister;
import com.kotsafe.security.HarWriter;
import com.kotsafe.security.HttpLog;
import com.kotsafe.security.Log;
import com.kotsafe.security.R;
import com.kotsafe.security.Utils;
import com.kotsafe.security.fragments.ConnectionPayload;
import com.kotsafe.security.fragments.HttpPayloadFragment;
import com.kotsafe.security.interfaces.ConnectionsListener;
import com.kotsafe.security.interfaces.PayloadHostActivity;
import com.kotsafe.security.model.ConnectionDescriptor;
import com.kotsafe.security.model.PayloadChunk;
import com.google.android.material.tabs.TabLayout;
import com.google.android.material.tabs.TabLayoutMediator;

import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class HttpDetailsActivity extends PayloadExportActivity implements ConnectionsListener, PayloadHostActivity {
    private static final String TAG = "HttpRequestDetailsActivity";
    public static final String HTTP_REQ_POS_KEY = "req_pos";
    public static final String FILTERED_POSITIONS_KEY = "filtered_positions";
    private HttpLog.HttpRequest mHttpReq;
    private ViewPager2 mPager;
    private StateAdapter mPagerAdapter;
    private int mReqPos;
    private ArrayList<Integer> mFilteredPositions;
    private int mFilteredIndex;
    private MenuItem mMenuPrev;
    private MenuItem mMenuNext;
    private MenuItem mMenuDisplayAs;
    private MenuItem mMenuInspectJwt;
    private MenuItem mMenuInspectProto;
    private MenuItem mMenuInspectDoh;
    private MenuItem mMenuEditResend;
    private String mDetectedJwt;
    private byte[] mDetectedProto;
    private byte[] mDetectedDoh;
    private String mDetectedDohBase64;
    private Boolean mDisplayMode;
    private Uri mHarFname;
    private AlertDialog mAlertDialog;

    private final ActivityResultLauncher<Intent> harFileLauncher =
            registerForActivityResult(new ActivityResultContracts.StartActivityForResult(), this::harFileResult);

    private static final int POS_REQUEST = 0;
    private static final int POS_REPLY = 1;
    private static final int POS_WEBSOCKET = 2;
    private boolean mHasWebsocket = false;
    private final ArrayList<PayloadHostActivity.ConnUpdateListener> mListeners = new ArrayList<>();
    private Handler mHandler;
    private boolean mListenerSet;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        displayBackAction();
        setContentView(R.layout.tabs_activity_fixed);

        mReqPos = getIntent().getIntExtra(HTTP_REQ_POS_KEY, -1);

        // Get filtered positions if provided
        mFilteredPositions = getIntent().getIntegerArrayListExtra(FILTERED_POSITIONS_KEY);
        mFilteredIndex = -1;

        // Find the index of the current position in the filtered list
        if (mFilteredPositions != null) {
            for (int i = 0; i < mFilteredPositions.size(); i++) {
                if (mFilteredPositions.get(i) == mReqPos) {
                    mFilteredIndex = i;
                    break;
                }
            }
            Log.d(TAG, "Using filtered navigation: " + mFilteredPositions.size() + " items, index=" + mFilteredIndex);
        }

        if(mReqPos != -1) {
            setTitle(String.format(getString(R.string.http_request_number), mReqPos + 1));

            HttpLog httpLog = CaptureService.getHttpLog();
            if(httpLog != null)
                mHttpReq = httpLog.getRequest(mReqPos);
        } else
            setTitle(R.string.http_requests);

        if(mHttpReq == null) {
            Log.w(TAG, "HTTP request with position " + mReqPos + " not found");
            finish();
            return;
        }

        // Check if this HTTP request has associated websocket data
        mHasWebsocket = mHttpReq.hasWebsocketData();

        mHandler = new Handler(Looper.getMainLooper());

        mPager = findViewById(R.id.pager);
        Utils.fixViewPager2Insets(mPager);
        setupTabs();
    }

    @Override
    public void onResume() {
        super.onResume();
        registerConnsListener();
    }

    @Override
    public void onPause() {
        super.onPause();
        unregisterConnsListener();
    }

    @Override
    protected void onDestroy() {
        if(mAlertDialog != null)
            mAlertDialog.dismiss();

        super.onDestroy();
    }

    private void setupTabs() {
        mPagerAdapter = new StateAdapter(this);
        mPager.setAdapter(mPagerAdapter);

        var tabLayout = (TabLayout) findViewById(R.id.tablayout);
        Utils.fixScrollableTabLayoutInsets(tabLayout);
        new TabLayoutMediator(tabLayout, mPager, (tab, position) ->
                tab.setText(getString(mPagerAdapter.getPageTitle(position)))
        ).attach();

        mPager.registerOnPageChangeCallback(new ViewPager2.OnPageChangeCallback() {
            @Override
            public void onPageSelected(int position) {
                updateMenuVisibility();
            }
        });
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        MenuInflater inflater = getMenuInflater();
        inflater.inflate(R.menu.http_details_menu, menu);

        mMenuPrev = menu.findItem(R.id.navigate_before);
        mMenuNext = menu.findItem(R.id.navigate_next);
        mMenuDisplayAs = menu.findItem(R.id.display_as);
        mMenuInspectJwt = menu.findItem(R.id.inspect_jwt);
        mMenuInspectProto = menu.findItem(R.id.inspect_proto);
        mMenuInspectDoh = menu.findItem(R.id.inspect_doh);
        mMenuEditResend = menu.findItem(R.id.edit_resend);
        MenuItem menuAiAudit = menu.findItem(R.id.ai_audit_request);
        if (menuAiAudit != null) menuAiAudit.setVisible(mHttpReq != null);

        updateNavigationButtons();
        updateMenuVisibility();
        return true;
    }

    private void updateNavigationButtons() {
        if(mMenuPrev == null || mMenuNext == null)
            return;

        boolean hasPrev, hasNext;

        if (mFilteredPositions != null) {
            // Using filtered navigation
            hasPrev = mFilteredIndex > 0;
            hasNext = mFilteredIndex < mFilteredPositions.size() - 1;
        } else {
            // Using unfiltered navigation
            HttpLog httpLog = CaptureService.getHttpLog();
            int httpLogSize = (httpLog != null) ? httpLog.getSize() : 0;
            hasPrev = mReqPos > 0;
            hasNext = mReqPos < httpLogSize - 1;
        }

        mMenuPrev.setEnabled(hasPrev);
        if(mMenuPrev.getIcon() != null)
            mMenuPrev.getIcon().setAlpha(hasPrev ? 255 : 80);

        mMenuNext.setEnabled(hasNext);
        if(mMenuNext.getIcon() != null)
            mMenuNext.getIcon().setAlpha(hasNext ? 255 : 80);
    }

    @Override
    public void updateMenuVisibility() {
        if(mMenuDisplayAs == null)
            return;

        mMenuDisplayAs.setVisible(true);
        if(mMenuEditResend != null)
            mMenuEditResend.setVisible(mHttpReq != null);
        detectAndConfigureJwt();
        detectAndConfigureProtobuf();
        detectAndConfigureDoh();

        Fragment currentFragment = getCurrentFragment();
        if(currentFragment instanceof HttpPayloadFragment payloadFragment) {
            if(mDisplayMode == null)
                mDisplayMode = true;

            payloadFragment.setDisplayMode(mDisplayMode);

            if(mDisplayMode)
                mMenuDisplayAs.setTitle(R.string.display_as_hexdump);
            else
                mMenuDisplayAs.setTitle(R.string.display_as_text);
        } else if(currentFragment instanceof ConnectionPayload wsFragment) {
            if(mDisplayMode == null)
                mDisplayMode = true;

            wsFragment.setDisplayMode(mDisplayMode);

            if(mDisplayMode)
                mMenuDisplayAs.setTitle(R.string.display_as_hexdump);
            else
                mMenuDisplayAs.setTitle(R.string.display_as_text);
        }
    }

    private void detectAndConfigureJwt() {
        if(mMenuInspectJwt == null)
            return;

        mDetectedJwt = null;
        if(mHttpReq != null) {
            // Check request URL
            String url = mHttpReq.getUrl();
            com.kotsafe.security.decoders.JwtDecoder.JwtTokenInfo info =
                    com.kotsafe.security.decoders.JwtDecoder.findAndParseJwt(url);

            // Check request chunk payload
            if(info == null && mHttpReq.conn != null && mHttpReq.firstChunkPos >= 0) {
                PayloadChunk chunk = mHttpReq.conn.getPayloadChunk(mHttpReq.firstChunkPos);
                if(chunk != null && chunk.payload != null) {
                    String text = new String(chunk.payload, java.nio.charset.StandardCharsets.UTF_8);
                    info = com.kotsafe.security.decoders.JwtDecoder.findAndParseJwt(text);
                }
            }

            // Check reply chunk payload
            if(info == null && mHttpReq.reply != null && mHttpReq.conn != null && mHttpReq.reply.firstChunkPos >= 0) {
                PayloadChunk replyChunk = mHttpReq.conn.getPayloadChunk(mHttpReq.reply.firstChunkPos);
                if(replyChunk != null && replyChunk.payload != null) {
                    String text = new String(replyChunk.payload, java.nio.charset.StandardCharsets.UTF_8);
                    info = com.kotsafe.security.decoders.JwtDecoder.findAndParseJwt(text);
                }
            }

            if(info != null) {
                mDetectedJwt = info.rawToken;
            }
        }

        mMenuInspectJwt.setVisible(mDetectedJwt != null);
    }

    private static byte[] extractBody(PayloadChunk chunk) {
        if (chunk == null || chunk.payload == null || chunk.payload.length == 0) return null;
        byte[] data = chunk.payload;
        for (int i = 0; i < data.length - 3; i++) {
            if (data[i] == '\r' && data[i + 1] == '\n' && data[i + 2] == '\r' && data[i + 3] == '\n') {
                return java.util.Arrays.copyOfRange(data, i + 4, data.length);
            }
        }
        return data;
    }

    private void detectAndConfigureProtobuf() {
        if (mMenuInspectProto == null) return;
        mDetectedProto = null;

        if (mHttpReq != null && mHttpReq.conn != null) {
            // Check reply first (most common for gRPC / Protobuf responses)
            if (mHttpReq.reply != null && mHttpReq.reply.firstChunkPos >= 0) {
                PayloadChunk replyChunk = mHttpReq.conn.getPayloadChunk(mHttpReq.reply.firstChunkPos);
                byte[] body = extractBody(replyChunk);
                if (body != null && body.length >= 2) {
                    if ((replyChunk.httpContentType != null && (replyChunk.httpContentType.contains("application/grpc") ||
                            replyChunk.httpContentType.contains("application/x-protobuf") ||
                            replyChunk.httpContentType.contains("application/protobuf"))) ||
                            com.kotsafe.security.decoders.ProtobufDecoder.detectAndDecode(body) != null) {
                        mDetectedProto = body;
                    }
                }
            }

            // Check request if reply wasn't protobuf
            if (mDetectedProto == null && mHttpReq.firstChunkPos >= 0) {
                PayloadChunk reqChunk = mHttpReq.conn.getPayloadChunk(mHttpReq.firstChunkPos);
                byte[] body = extractBody(reqChunk);
                if (body != null && body.length >= 2) {
                    if ((reqChunk.httpContentType != null && (reqChunk.httpContentType.contains("application/grpc") ||
                            reqChunk.httpContentType.contains("application/x-protobuf") ||
                            reqChunk.httpContentType.contains("application/protobuf"))) ||
                            com.kotsafe.security.decoders.ProtobufDecoder.detectAndDecode(body) != null) {
                        mDetectedProto = body;
                    }
                }
            }
        }

        mMenuInspectProto.setVisible(mDetectedProto != null);
    }

    private void detectAndConfigureDoh() {
        if (mMenuInspectDoh == null) return;
        mDetectedDoh = null;
        mDetectedDohBase64 = null;

        if (mHttpReq != null) {
            // Check URL query for ?dns=
            String url = mHttpReq.getUrl();
            if (url != null && url.contains("dns=")) {
                int idx = url.indexOf("dns=");
                String sub = url.substring(idx + 4);
                int amp = sub.indexOf('&');
                if (amp >= 0) sub = sub.substring(0, amp);
                if (!sub.isEmpty()) {
                    mDetectedDohBase64 = sub;
                }
            }

            if (mHttpReq.conn != null) {
                // Check reply body (DNS response)
                if (mHttpReq.reply != null && mHttpReq.reply.firstChunkPos >= 0) {
                    PayloadChunk replyChunk = mHttpReq.conn.getPayloadChunk(mHttpReq.reply.firstChunkPos);
                    byte[] body = extractBody(replyChunk);
                    if (body != null && body.length >= 12) {
                        if ((replyChunk.httpContentType != null && replyChunk.httpContentType.contains("application/dns-message")) ||
                                com.kotsafe.security.decoders.DohDecoder.decode(body) != null) {
                            mDetectedDoh = body;
                        }
                    }
                }

                // Check request body (POST DNS query)
                if (mDetectedDoh == null && mDetectedDohBase64 == null && mHttpReq.firstChunkPos >= 0) {
                    PayloadChunk reqChunk = mHttpReq.conn.getPayloadChunk(mHttpReq.firstChunkPos);
                    byte[] body = extractBody(reqChunk);
                    if (body != null && body.length >= 12) {
                        if ((reqChunk.httpContentType != null && reqChunk.httpContentType.contains("application/dns-message")) ||
                                com.kotsafe.security.decoders.DohDecoder.decode(body) != null) {
                            mDetectedDoh = body;
                        }
                    }
                }
            }
        }

        mMenuInspectDoh.setVisible(mDetectedDoh != null || mDetectedDohBase64 != null);
    }

    private Fragment getCurrentFragment() {
        int currentTab = mPager.getCurrentItem();
        String tag = "f" + mPagerAdapter.getItemId(currentTab);
        return getSupportFragmentManager().findFragmentByTag(tag);
    }

    @Override
    public boolean onOptionsItemSelected(@NonNull MenuItem item) {
        int itemId = item.getItemId();

        if(itemId == R.id.navigate_before) {
            navigateToPrevious();
            return true;
        } else if(itemId == R.id.navigate_next) {
            navigateToNext();
            return true;
        } else if(itemId == R.id.inspect_jwt) {
            if(mDetectedJwt != null) {
                com.kotsafe.security.views.JwtInspectorDialog.newInstance(mDetectedJwt)
                        .show(getSupportFragmentManager(), com.kotsafe.security.views.JwtInspectorDialog.TAG);
            }
            return true;
        } else if(itemId == R.id.inspect_proto) {
            if(mDetectedProto != null) {
                com.kotsafe.security.views.ProtobufInspectorDialog.newInstance(mDetectedProto)
                        .show(getSupportFragmentManager(), com.kotsafe.security.views.ProtobufInspectorDialog.TAG);
            }
            return true;
        } else if(itemId == R.id.inspect_doh) {
            if(mDetectedDohBase64 != null) {
                com.kotsafe.security.views.DohInspectorDialog.newInstanceFromBase64Url(mDetectedDohBase64)
                        .show(getSupportFragmentManager(), com.kotsafe.security.views.DohInspectorDialog.TAG);
            } else if(mDetectedDoh != null) {
                com.kotsafe.security.views.DohInspectorDialog.newInstance(mDetectedDoh)
                        .show(getSupportFragmentManager(), com.kotsafe.security.views.DohInspectorDialog.TAG);
            }
            return true;
        } else if(itemId == R.id.ai_audit_request) {
            if(mReqPos >= 0) {
                com.kotsafe.security.views.HttpAiAuditDialog.newInstance(mReqPos)
                        .show(getSupportFragmentManager(), "HttpAiAuditDialog");
            }
            return true;
        } else if(itemId == R.id.edit_resend) {
            if(mHttpReq != null) {
                Intent repeaterIntent = HttpRepeaterActivity.createIntentFromHttpLog(this, mHttpReq);
                startActivity(repeaterIntent);
            }
            return true;
        } else if(itemId == R.id.display_as) {
            if(mDisplayMode != null) {
                mDisplayMode = !mDisplayMode;
                updateMenuVisibility();
            }
            return true;
        } else if(itemId == R.id.save_as_har) {
            openHarFileSelector();
            return true;
        }

        return super.onOptionsItemSelected(item);
    }

    private void navigateToPrevious() {
        if (mFilteredPositions != null) {
            if (mFilteredIndex > 0) {
                mFilteredIndex--;
                mReqPos = mFilteredPositions.get(mFilteredIndex);
                loadHttpRequest();
            }
        } else {
            if (mReqPos > 0) {
                mReqPos--;
                loadHttpRequest();
            }
        }
    }

    private void navigateToNext() {
        if (mFilteredPositions != null) {
            if (mFilteredIndex < mFilteredPositions.size() - 1) {
                mFilteredIndex++;
                mReqPos = mFilteredPositions.get(mFilteredIndex);
                loadHttpRequest();
            }
        } else {
            HttpLog httpLog = CaptureService.getHttpLog();
            int httpLogSize = (httpLog != null) ? httpLog.getSize() : 0;

            if (mReqPos < httpLogSize - 1) {
                mReqPos++;
                loadHttpRequest();
            }
        }
    }

    private void loadHttpRequest() {
        HttpLog httpLog = CaptureService.getHttpLog();
        if(httpLog != null) {
            mHttpReq = httpLog.getRequest(mReqPos);

            if(mHttpReq != null) {
                setTitle(String.format(getString(R.string.http_request_number), mReqPos + 1));

                // Check if this HTTP request has associated websocket data
                mHasWebsocket = mHttpReq.hasWebsocketData();

                int currentTab = mPager.getCurrentItem();

                setupTabs();

                // Restore tab position if still valid for the new request
                int newItemCount = mPagerAdapter.getItemCount();
                if (currentTab < newItemCount) {
                    // Tab is still valid, restore it
                    mPager.setCurrentItem(currentTab, false);
                } else {
                    // Tab not available (e.g., no response), fall back to first tab
                    mPager.setCurrentItem(0, false);
                }

                updateNavigationButtons();
                updateMenuVisibility();
            } else {
                Log.w(TAG, "HTTP request with position " + mReqPos + " not found");
            }
        }
    }

    private void registerConnsListener() {
        ConnectionsRegister reg = CaptureService.getConnsRegister();

        if((reg != null) && !mListenerSet) {
            if(mHttpReq.conn.status < ConnectionDescriptor.CONN_STATUS_CLOSED) {
                Log.d(TAG, "Adding connections listener");
                reg.addListener(this);
                mListenerSet = true;
            }
        }

        dispatchConnUpdate();
    }

    private void unregisterConnsListener() {
        if(mListenerSet) {
            ConnectionsRegister reg = CaptureService.getConnsRegister();

            if(reg != null) {
                Log.d(TAG, "Removing connections listener");
                reg.removeListener(this);
            }

            mListenerSet = false;
        }
    }

    @Override
    public void connectionsChanges(int num_connections) {
        if (mHandler != null)
            mHandler.post(this::dispatchConnUpdate);
    }

    @Override
    public void connectionsAdded(int start, ConnectionDescriptor[] conns) {}

    @Override
    public void connectionsRemoved(int start, ConnectionDescriptor[] conns) {}

    @Override
    public void connectionsUpdated(int[] positions) {
        ConnectionsRegister reg = CaptureService.getConnsRegister();

        if((reg == null) || (mHttpReq == null))
            return;

        for(int pos : positions) {
            ConnectionDescriptor conn = reg.getConn(pos);

            if((conn != null) && (conn.incr_id == mHttpReq.conn.incr_id)) {
                mHandler.post(this::dispatchConnUpdate);
                break;
            }
        }
    }

    @Override
    public void addConnUpdateListener(PayloadHostActivity.ConnUpdateListener listener) {
        mListeners.add(listener);
    }

    @Override
    public void removeConnUpdateListener(PayloadHostActivity.ConnUpdateListener listener) {
        mListeners.remove(listener);
    }

    private void dispatchConnUpdate() {
        for(PayloadHostActivity.ConnUpdateListener listener: mListeners)
            listener.connectionUpdated();

        // Check if websocket tab needs to be added
        if(!mHasWebsocket && (mHttpReq != null) && mHttpReq.hasWebsocketData()) {
            mHasWebsocket = true;
            mPagerAdapter.notifyDataSetChanged();
        }

        if((mHttpReq != null) && (mHttpReq.conn.status >= ConnectionDescriptor.CONN_STATUS_CLOSED))
            unregisterConnsListener();
    }

    private void openHarFileSelector() {
        if (mHttpReq == null)
            return;

        boolean noFileDialog = false;
        String fname = Utils.getExportFileName(this, "har");
        Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("*/*");
        intent.putExtra(Intent.EXTRA_TITLE, fname);

        if(Utils.supportsFileDialog(this, intent)) {
            try {
                harFileLauncher.launch(intent);
            } catch (ActivityNotFoundException e) {
                noFileDialog = true;
            }
        } else
            noFileDialog = true;

        if(noFileDialog) {
            Log.d(TAG, "No app found to handle file selection");

            Uri uri = Utils.getDownloadsUri(this, fname);

            if(uri != null) {
                mHarFname = uri;
                exportHar();
            } else
                Utils.showToastLong(this, R.string.no_activity_file_selection);
        }
    }

    private void exportHar() {
        if(mHarFname == null || mHttpReq == null)
            return;

        Log.d(TAG, "Writing HAR file: " + mHarFname);

        ExecutorService executor = Executors.newSingleThreadExecutor();
        Handler handler = new Handler(Looper.getMainLooper());
        final boolean[] cancelled = {false};

        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        builder.setTitle(R.string.exporting);
        builder.setMessage(R.string.export_in_progress);
        builder.setNegativeButton(android.R.string.cancel, (dialog, which) -> {
            Log.i(TAG, "Abort HAR export");
            cancelled[0] = true;
            executor.shutdownNow();
        });

        mAlertDialog = builder.create();
        mAlertDialog.setCanceledOnTouchOutside(false);
        mAlertDialog.show();

        mAlertDialog.setOnCancelListener(dialog -> {
            Log.i(TAG, "Abort HAR export (back button)");
            cancelled[0] = true;
            executor.shutdownNow();
        });
        mAlertDialog.setOnDismissListener(dialog -> mAlertDialog = null);

        final Uri harFname = mHarFname;
        final HttpLog.HttpRequest httpReq = mHttpReq;
        mHarFname = null;

        executor.execute(() -> {
            boolean success = false;

            try {
                OutputStream stream = getContentResolver().openOutputStream(harFname, "rwt");

                if(stream != null) {
                    HarWriter writer = new HarWriter(HttpDetailsActivity.this, httpReq);
                    writer.write(stream);
                    stream.close();
                    success = true;
                }
            } catch (IOException e) {
                if(!cancelled[0])
                    e.printStackTrace();
            }

            if(cancelled[0])
                return;

            final boolean result = success;
            final Utils.UriStat stat = result ? Utils.getUriStat(HttpDetailsActivity.this, harFname) : null;

            handler.post(() -> {
                if(mAlertDialog != null)
                    mAlertDialog.dismiss();

                if(result) {
                    if(stat != null)
                        Utils.showToast(HttpDetailsActivity.this, R.string.file_saved_with_name, stat.name);
                    else
                        Utils.showToast(HttpDetailsActivity.this, R.string.save_ok);
                } else
                    Utils.showToast(HttpDetailsActivity.this, R.string.cannot_write_file);
            });
        });
    }

    private void harFileResult(final ActivityResult result) {
        if((result.getResultCode() == RESULT_OK) && (result.getData() != null)) {
            mHarFname = result.getData().getData();
            exportHar();
        } else {
            mHarFname = null;
        }
    }

    private class StateAdapter extends FragmentStateAdapter {
        StateAdapter(final FragmentActivity fa) { super(fa); }

        @NonNull
        @Override
        public Fragment createFragment(int position) {
            //Log.d(TAG, "createFragment");
            int req_pos = mHttpReq.getPosition();
            int pos = getVisibleTabsPositions()[position];

            switch (pos) {
                case POS_REPLY:
                    return HttpPayloadFragment.newInstance(req_pos, true);
                case POS_WEBSOCKET:
                    return ConnectionPayload.newInstance(PayloadChunk.ChunkType.WEBSOCKET, mHttpReq.conn.incr_id);
                case POS_REQUEST:
                default:
                    return HttpPayloadFragment.newInstance(req_pos, false);
            }
        }

        @Override
        public int getItemCount() {
            // Request and Response tabs are always shown (standard HTTP inspector)
            // Websocket tab is added when websocket data is present
            int count = 2; // Request + Response
            if (mHasWebsocket)
                count++;   // Websocket tab
            return count;
        }

        public int getPageTitle(final int position) {
            int pos = getVisibleTabsPositions()[position];

            switch (pos) {
                case POS_REPLY:
                    return R.string.response;
                case POS_WEBSOCKET:
                    return R.string.websocket;
                default:
                    return R.string.request;
            }
        }

        public int[] getVisibleTabsPositions() {
            int[] visible = new int[getItemCount()];
            int i = 0;

            visible[i++] = POS_REQUEST;
            visible[i++] = POS_REPLY;
            if (mHasWebsocket)
                visible[i] = POS_WEBSOCKET;

            return visible;
        }
    }
}
