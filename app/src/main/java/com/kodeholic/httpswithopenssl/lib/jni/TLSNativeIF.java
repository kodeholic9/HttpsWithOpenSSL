package com.kodeholic.httpswithopenssl.lib.jni;

import android.content.Context;

import androidx.annotation.NonNull;


import com.kodeholic.httpswithopenssl.lib.util.Log;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.SocketTimeoutException;

public class TLSNativeIF {
    public static final String TAG = "TI2TLS";
    public static final String LIB_NAME = "ti2tls_jni";

    public static final int MAX_WRITTEN_SIZE = 2048;

    private Context mContext;
    private int tlsconnId = -1;
    private InetAddress localAddress;

    private TLSInputStream  iStream;
    private TLSOutputStream oStream;

    //lib를 load한다.
    static {
        loadLibrary();
    }

    public TLSNativeIF(Context context) {
        mContext = context;
        //
        iStream= new TLSInputStream();
        oStream= new TLSOutputStream();
    }

    /**
     * 라이브러리를 로드한다.
     */
    public static void loadLibrary() {
        Log.d(TAG, "loadLibrary() - name: " + LIB_NAME);
        System.loadLibrary(LIB_NAME);

        //initialize....
        tlsmagic_initialize();
    }


    /**
     * TLS 연결을 open한다.
     * @param host
     * @param port
     * @return
     */
    public int tlsOpen(int type, String host, int port, byte[] cert, int timeo) {
        Log.d(TAG, "tlsOpen() - tlsconnId[" + tlsconnId + "]"
                + ", type: " + type
                + ", host: " + host
                + ", port: " + port
                + ", timeo: " + timeo);

        //TODO - ECDSA용 RootCA.crt를 로컬에서 참조
//        try {
//            InputStream in = mContext.getResources().openRawResource(R.raw.ca);
//            if (in != null) {
//                byte[] temp = new byte[in.available()];
//                in.read(temp, 0, temp.length);
//                //
//                cert = temp;
//
//                //don't forget!
//                in.close();
//            }
//        }
//        catch(Exception e) {
//            e.printStackTrace();
//        }

        //TLS 연결한다.
        byte[] localIp = new byte[128];
        if ((tlsconnId = tls_open(type, host, port, cert, cert.length, localIp, timeo)) == -1) {
            Log.e(TAG, "tlsOpen() - fail to tls_open()");
            return -1;
        }

        int realLen = 0;
        while (realLen < localIp.length && localIp[realLen] != 0x00) {
            realLen++;
        }

        //로컬 주소를 설정한다.
        try {
            localAddress = InetAddress.getByName(new String(localIp, 0, realLen, "UTF-8"));
        }
        catch (Exception e) {
            e.printStackTrace();
        }
        if (localAddress == null) {
            Log.e(TAG, "tlsOpen() - fail to InetAddress.getByName()");
            return -1;
        }

        return tlsconnId;
    }

    /**
     * TLS 연결을 close한다.
     */
    public void tlsClose() {
        Log.d(TAG, "tlsClose() - tlsconnId[" + tlsconnId + "]");
        if (tlsconnId != -1) {
            tls_close(tlsconnId);
            tlsconnId = -1;
        }

        return;
    }

    /**
     * TLS 소켓단에 에러 유발
     */
    public void tlsShutdown() {
        Log.d(TAG, "tlsShutdown() - tlsconnId[" + tlsconnId + "]");
        if (tlsconnId != -1) {
            // shutdown 시그널 전송에 실패한 경우, close를 수행한다.
            if (tls_signal(tlsconnId, 1) == -1) {
                Log.d(TAG, "tlsShutdown() - tlsconnId[" + tlsconnId + "], tls_signal failed! close!!");
                tlsClose();
            }
        }

        return;
    }

    public TLSInputStream getInputStream() {
        return iStream;
    }

    public TLSOutputStream getOutputStream() {
        return oStream;
    }

    public InetAddress getLocalAddress() {
        return localAddress;
    }

    /**
     * 전용 inputstream을 정의한다.
     */
    public class TLSInputStream extends InputStream {
        @Override
        public int read() throws IOException {
            throw new IOException("not implemented!");
        }

        @Override
        public int read(@NonNull byte[] b, int off, int len) throws IOException {
            return read(b, off, len, 0);
        }

        /**
         * TLS 소켓으로 부터 읽는다
         * @param b
         * @param off
         * @param len
         * @return the total number of bytes read into the buffer, or -1 if there is no more data because the end of the stream has been reached.
         * @throws IOException
         */
        public int read(@NonNull byte[] b, int off, int len, int timeo) throws IOException {
            //파라미터 체크
            if (b == null) {
                throw new NullPointerException();
            }
            else if (off < 0 || len < 0 || (off + len) > b.length) {
                throw new IndexOutOfBoundsException();
            }
            else if (len == 0) {
                return 0;
            }

            //JNI 호출 (결과 값에 대해 java향으로 치환)
            int result = tls_read(tlsconnId, b, off, len, timeo);
            if (result == -1) {
                throw new IOException("tls_read() returns ... " + result);
            }
            else if (result == -2) {
                throw new SocketTimeoutException("tls_read() returns ... " + result);
            }
            else if (result == 0) {
                result = -1;
            }

            return result;
        }
    };

    /**
     * 전용 outputstream을 정의한다.
     */
    public class TLSOutputStream extends OutputStream {
        @Override
        public void write(int b) throws IOException {
            throw new IOException("not implemented!");
        }

        @Override
        public void write(@NonNull byte[] b, int off, int len) throws IOException {
            //파라미터 체크
            if (b == null) {
                throw new NullPointerException();
            }
            else if ((off < 0) || (len < 0) || ((off + len) > b.length)) {
                throw new IndexOutOfBoundsException();
            }
            else if (len == 0) {
                return;
            }

            //JNI 호출 (1024 이상 write하지 못하도록 조정한다.)
            int nWritten = 0;
            int nLeft    = len;
            while (nLeft > 0) {
                int min = Math.min(MAX_WRITTEN_SIZE, nLeft);
                int n   = tls_write(tlsconnId, b, off+nWritten, min, 0);
                if (n <= 0) {
                    throw new IOException("tls_write error!");
                }
//                Log.d(TAG, "write(1) - n: " + n + ", nLeft: " + nLeft + ", nWritten: " + nWritten);
                nLeft    -= n;
                nWritten += n;
//                Log.d(TAG, "write(2) - n: " + n + ", nLeft: " + nLeft + ", nWritten: " + nWritten);
            }
        }
    }

    //////////////////////////////////////////////////////////////
    //
    // JNI 함수 정의
    //
    ////////////////////////////////////////////////////////////////
    private static native int tlsmagic_initialize();
    private native int tls_open (int type, String host, int port, byte[] cert, int cert_len, byte[] local_ip, int timeo);
    private native int tls_close(int tlsconn_id);
    private native int tls_read (int tlsconn_id, byte[] bytes, int off, int len, int timeo);
    private native int tls_write(int tlsconn_id, byte[] bytes, int off, int len, int timeo);
    private native int tls_signal(int tlsconn_id, int b);

}
