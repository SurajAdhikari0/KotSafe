package com.kotsafe.security.model;

import android.app.Activity;
import android.app.Application;
import android.app.AlertDialog;
import android.os.Build;
import android.os.Bundle;
import android.view.WindowManager;
import java.util.WeakHashMap;
import java.util.function.Consumer;

/** OS-confirmed visibility of KotSafe's own windows only. No cross-app capture claims. */
public final class ScreenCaptureConsent implements Application.ActivityLifecycleCallbacks {
    private final WeakHashMap<Activity,Consumer<Integer>> callbacks=new WeakHashMap<>();
    private boolean acknowledged=false;
    private AlertDialog warning;
    public static void install(Application app){if(Build.VERSION.SDK_INT>=35)app.registerActivityLifecycleCallbacks(new ScreenCaptureConsent());}
    @Override public void onActivityResumed(Activity activity){
        if(Build.VERSION.SDK_INT<35 || activity.isFinishing())return;
        Consumer<Integer> callback=state->{
            if(state==WindowManager.SCREEN_RECORDING_STATE_NOT_VISIBLE){acknowledged=false;return;}
            if(state!=WindowManager.SCREEN_RECORDING_STATE_VISIBLE || acknowledged || activity.isFinishing() || activity.isDestroyed() || warning!=null)return;
            warning=new AlertDialog.Builder(activity).setTitle("KotSafe is visible in a screen recording")
                .setMessage("People viewing the recording may see account and security information. Stop screen sharing before entering passwords, payment details or recovery codes. KotSafe cannot confirm protection of other apps.")
                .setCancelable(false)
                .setNegativeButton("Hide KotSafe",(dialog,which)->{activity.moveTaskToBack(true);})
                .setPositiveButton("I understand the risk",(dialog,which)->{acknowledged=true;})
                .create();
            warning.setOnDismissListener(dialog->warning=null);warning.show();
        };
        try{callbacks.put(activity,callback);int state=activity.getWindowManager().addScreenRecordingCallback(activity.getMainExecutor(),callback);callback.accept(state);}
        catch(SecurityException|UnsupportedOperationException error){callbacks.remove(activity);}
    }
    @Override public void onActivityPaused(Activity activity){
        if(Build.VERSION.SDK_INT<35)return;
        Consumer<Integer> callback=callbacks.remove(activity);if(callback!=null)try{activity.getWindowManager().removeScreenRecordingCallback(callback);}catch(RuntimeException ignored){}
        if(warning!=null){warning.dismiss();warning=null;}
    }
    @Override public void onActivityCreated(Activity activity,Bundle state){}
    @Override public void onActivityStarted(Activity activity){}
    @Override public void onActivityStopped(Activity activity){}
    @Override public void onActivitySaveInstanceState(Activity activity,Bundle state){}
    @Override public void onActivityDestroyed(Activity activity){callbacks.remove(activity);}
}
