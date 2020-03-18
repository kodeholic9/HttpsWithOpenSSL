package com.kodeholic.httpswithopenssl.common;

import android.app.Activity;
import android.app.ProgressDialog;
import android.content.Context;
import android.os.Handler;
import android.os.Looper;
import android.widget.Toast;

import com.kodeholic.httpswithopenssl.lib.util.Log;


public class PopupManager {
    public static final String TAG = PopupManager.class.getSimpleName();

    private volatile static PopupManager sInstance;

    private Context mContext = null;
    private Handler mHandler = null;
    private Toast mToast = null;
    private ProgressDialog mLoading = null;

    private PopupManager(Context context) {
        mContext = context;
        mHandler = new Handler(Looper.getMainLooper());
    }

    public static PopupManager getInstance(Context context) {
        if (sInstance == null) {
            synchronized (PopupManager.class) {
                if (sInstance == null) {
                    sInstance = new PopupManager(context);
                }
            }
        }
        return sInstance;
    }

    private void _showToast(String msg, int duration) {
        try {
            if (mToast != null) {
                mToast.cancel();
                mToast = null;
            }

            mToast = Toast.makeText(mContext.getApplicationContext(), msg, duration);
            mToast.show();

            Log.d(TAG, "showToast() - " + msg);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return;
    }

    public void showToast(final String msg, final int duration) {
        mHandler.post(new Runnable() {
            @Override
            public void run() {
                _showToast(msg, duration);
            }
        });
    }

    public void showToast(int resId, final int duration) {
        showToast(mContext.getString(resId), duration);
    }

    public void showToast(final String msg) {
        showToast(msg, Toast.LENGTH_SHORT);
    }

    public void showToast(int resId) {
        showToast(mContext.getString(resId), Toast.LENGTH_SHORT);
    }


    /**
     * 로딩을 시작한다.
     *
     * @param activity
     * @param f
     */
    public void showLoading(final Activity activity, String f) {
        Log.d(TAG, "showLoading() - f: " + f);
        mHandler.post(new Runnable() {
            @Override
            public void run() {
                _showLoading(activity);
            }
        });
    }

    private synchronized void _showLoading(Activity activity) {
        if (mLoading != null) {
            return;
        }
        mLoading = new ProgressDialog(activity);
        mLoading.show(mContext, "", "Searching....");
    }
}
