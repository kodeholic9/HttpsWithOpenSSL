package com.kodeholic.httpswithopenssl.common;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;

import com.kodeholic.httpswithopenssl.common.data.Book;
import com.kodeholic.httpswithopenssl.common.data.BookDetailRes;
import com.kodeholic.httpswithopenssl.common.data.BookListRes;
import com.kodeholic.httpswithopenssl.lib.http.HttpInvoker;
import com.kodeholic.httpswithopenssl.lib.http.HttpListener;
import com.kodeholic.httpswithopenssl.lib.http.HttpRequest;
import com.kodeholic.httpswithopenssl.lib.http.HttpResponse;
import com.kodeholic.httpswithopenssl.lib.util.EReason;
import com.kodeholic.httpswithopenssl.lib.util.JSUtil;
import com.kodeholic.httpswithopenssl.lib.util.Log;

import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;

public class BookManager {
    public static final String TAG = BookManager.class.getSimpleName();

    public static final int GET_NEW_LIST = 0;
    public static final int GET_SEARCH   = 1;
    public static final int GET_DETAIL   = 2;

    public static final String URL_NEW_LIST= "https://api.itbook.store/1.0/new";
    public static final String URL_SEARCH  = "https://api.itbook.store/1.0/search"; // + /{query}/{page}
    public static final String URL_DETAIL  = "https://api.itbook.store/1.0/books";  // + /{isbn13}

    public class BookApiInvoker extends HttpInvoker {
        public BookApiInvoker(Context context) {
            super(context, false);
        }

        public int invoke(int invokeType, String url, HttpListener listener) {
            return invoke(invokeType, new HttpRequestImpl(url), listener);
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

    public interface Listener {
        void onResponse(HttpResponse response);
    }

    private volatile static BookManager sInstance;

    private Context mContext = null;
    private Handler mHandler = null;

    private BookManager(Context context) {
        mContext = context;
        mHandler = new Handler(Looper.getMainLooper());
    }

    public static BookManager getInstance(Context context) {
        if (sInstance == null) {
            synchronized (BookManager.class) {
                if (sInstance == null) {
                    sInstance = new BookManager(context);
                }
            }
        }
        return sInstance;
    }

    private String getEncodedString(String queryString) {
        try {
            return URLEncoder.encode(queryString, "UTF-8");
        }
        catch (Exception e) {
            e.printStackTrace();
        }

        return queryString;
    }

    private final int checkReason(int reason, Listener l) {
        if (reason != EReason.I_EOK) {
            HttpResponse error = new HttpResponse(reason);
            if (l != null) {
                l.onResponse(error);
            }
        }

        return reason;
    }

    private final void checkResponse(HttpResponse response, Class classOfT, Listener l) {
        //디버깅..
        if (response.isFAIL()) {
            PopupManager.getInstance(mContext).showToast("An error occurred during server request.\n" + response.toDisplay());
        }

        if (l == null) {
            return;
        }

        //실패인 경우, 즉시 반환
        if (response.isFAIL()) {
            l.onResponse(response);
            return;
        }

        //응답 메시지 파싱
        try {
            if (classOfT != null) {
                Object o = JSUtil.json2Object(response, classOfT);
//                if (o instanceof IResponse) {
//                    int error = ((IResponse)o).getError();
//                    if (error != 0) {
//                        showToast("Error: " + error);
//                    }
//                }
                response.setObject(o);
            }
            l.onResponse(response);
            return;
        }
        catch (Exception e) {
            e.printStackTrace();
        }

        //파싱 오류
        l.onResponse(new HttpResponse(EReason.I_ERESPONSE));
    }

    /**
     * 서버로 부터 새 목록을 조회한다.
     * @param listener
     * @return
     */
    public BookApiInvoker newList(final Listener listener, String f) {
        String url = URL_NEW_LIST;

        Log.d(TAG, "newList() - f: " + f + ", url: " + url);

        BookApiInvoker invoker = new BookApiInvoker(mContext);
        int result = invoker.invoke(GET_NEW_LIST, url, new HttpListener() {
            @Override public void onProgress(int httpSequence, int current, int total) { }
            @Override
            public void onResponse(int httpSequence, int httpReason, HttpResponse httpResponse) {
                checkResponse(httpResponse, BookListRes.class, listener);
            }
        });

        checkReason(result != -1 ? EReason.I_EOK : EReason.I_UNKNOWN_ERR, listener);

        return (result != -1) ? invoker : null;
    }

    /**
     * 서버로 검색 요청을 한다.
     * @param queryString
     * @param pageNo
     * @param listener
     * @param f
     * @return
     */
    public BookApiInvoker search(String queryString, int pageNo, final Listener listener, String f) {
        Log.d(TAG, "search() - f: " + f + ", queryString: " + queryString + ", pageNo: " + pageNo);

        String url  = URL_SEARCH + "/" + getEncodedString(queryString) + "/" + pageNo;

        BookApiInvoker invoker = new BookApiInvoker(mContext);
        int result = invoker.invoke(GET_SEARCH, url, new HttpListener() {
            @Override public void onProgress(int httpSequence, int current, int total) { }
            @Override
            public void onResponse(int httpSequence, int httpReason, HttpResponse httpResponse) {
                checkResponse(httpResponse, BookListRes.class, listener);
            }
        });

        checkReason(result != -1 ? EReason.I_EOK : EReason.I_UNKNOWN_ERR, listener);

        return (result != -1) ? invoker : null;
    }

    /**
     * 서버로 상세 정보를 요청한다.
     * @param isbn13
     * @param listener
     * @return
     */
    public BookApiInvoker detail(String isbn13, final Listener listener, String f) {
        String url = URL_DETAIL + "/" + isbn13;

        Log.d(TAG, "detail() - f: " + f + ", isbn13: " + isbn13 + ", url: " + url);

        BookApiInvoker invoker = new BookApiInvoker(mContext);
        int result = invoker.invoke(GET_DETAIL, url, new HttpListener() {
            @Override public void onProgress(int httpSequence, int current, int total) { }
            @Override
            public void onResponse(int httpSequence, int httpReason, HttpResponse httpResponse) {
                checkResponse(httpResponse, BookDetailRes.class, listener);
            }
        });

        checkReason(result != -1 ? EReason.I_EOK : EReason.I_UNKNOWN_ERR, listener);

        return (result != -1) ? invoker : null;
    }
}
