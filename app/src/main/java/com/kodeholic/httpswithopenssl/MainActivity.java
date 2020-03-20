package com.kodeholic.httpswithopenssl;

import androidx.appcompat.app.AppCompatActivity;

import android.content.Context;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

import com.kodeholic.httpswithopenssl.common.PopupManager;
import com.kodeholic.httpswithopenssl.lib.http.HttpInvoker;
import com.kodeholic.httpswithopenssl.lib.http.HttpListener;
import com.kodeholic.httpswithopenssl.lib.http.HttpRequest;
import com.kodeholic.httpswithopenssl.lib.http.HttpResponse;

public class MainActivity extends AppCompatActivity {
    public static final String TAG = MainActivity.class.getSimpleName();

    private Context mContext;

    private Button bt_invoke;
    private TextView tv_result;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        mContext = this;
        bt_invoke = findViewById(R.id.bt_invoke);
        tv_result = findViewById(R.id.tv_result);

        bt_invoke.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                SampleInvoker invoker = new SampleInvoker(mContext);
                invoker.invoke("https://www.googleapis.com/youtube/v3/channels?part=contentDetails", new HttpListener() {
                    @Override public void onProgress(int httpSequence, int current, int total) { }
                    @Override
                    public void onResponse(int httpSequence, int httpReason, HttpResponse httpResponse) {
                        updateView(httpResponse.getContents());
                    }
                });
            }
        });
    }

    private void updateView(final String result) {
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                tv_result.setText(result);
            }
        });
    }

    public class SampleInvoker extends HttpInvoker {
        public SampleInvoker(Context context) {
            super(context, false);
        }

        public int invoke(String url, HttpListener listener) {
            return invoke(0, new HttpRequestImpl(url), listener);
        }

        private class HttpRequestImpl extends HttpRequest {
            private String url;
            public HttpRequestImpl(String url) {
                super(getContext());
                this.url = url;
            }

            @Override
            public int onRequest() throws Exception {
                mHttp.putPath(this.url);
                return mHttp.get();
            }

            @Override
            public void onResponse(int sequence, int reason, HttpResponse response) {
                onComplete(sequence, reason, response);
            }
        }
    }
}
