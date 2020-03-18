package com.kodeholic.httpswithopenssl.lib.http;

import android.content.Context;
import android.text.TextUtils;

import androidx.annotation.NonNull;


import com.kodeholic.httpswithopenssl.lib.jni.TLSNativeIF;
import com.kodeholic.httpswithopenssl.lib.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class TLSURLConnection extends HttpURLConnection {
    public static final String TAG = TLSURLConnection.class.getSimpleName();

    private final static String  CRLF = "\r\n";

    private Context     mContext;
    private TLSNativeIF mNative;

    private TLSURLInputStream mIStream;

    protected TLSURLConnection(URL u) {
        super(u);
    }

    protected TLSURLConnection(Context context, URL u) {
        super(u);
        mContext = context;
        mNative  = new TLSNativeIF(mContext);
        mIStream = new TLSURLInputStream();
        //
        mRequestHeaderFields = new HashMap<String,List<String>>();
        mRequestHeaderList   = new ArrayList<>();
        //
        mResponseHeaderFields = new HashMap<String,List<String>>();
        mResponseHeaderList   = new ArrayList<>();
    }

    @Override
    public InputStream getInputStream() throws IOException {
        Log.d(TAG, "getInputStream()");
        if (responseCode == -1) {
            parse();
        }

        return mIStream;
    }

    @Override
    public InputStream getErrorStream() {
        return mIStream;
    }

    @Override
    public OutputStream getOutputStream() throws IOException {
        Log.d(TAG, "getOutputStream()");
        if (!connected) {
            //연결하고, 요청 헤더 정보를 전송한다.
            sendRequestHeader();
        }
        return mNative.getOutputStream();
    }

    @Override
    public int getResponseCode() throws IOException {
        Log.d(TAG, "getResponseCode()");
        if (responseCode != -1) {
            return responseCode;
        }
        if (!connected) {
            //연결하고, 요청 헤더 정보를 전송한다.
            sendRequestHeader();
        }
        parse();

        return responseCode;
    }

    @Override
    public String getHeaderFieldKey(int n) {
        synchronized (mResponseHeaderFields) {
            if (mResponseHeaderList.size() > n) {
                return mResponseHeaderList.get(n);
            }
        }

        return null;
    }

    @Override
    public String getHeaderField(int n) {
        synchronized (mResponseHeaderFields) {
            String name = getHeaderFieldKey(n);
            if (name != null) {
                return getHeaderField(name);
            }
        }

        return null;
    }

    @Override
    public String getHeaderField(String name) {
        synchronized (mResponseHeaderFields) {
            List<String> fields = mResponseHeaderFields.get(name.toLowerCase());
            if (fields != null && fields.size() > 0) {
                return fields.get(0);
            }
        }

        return null;
    }

    private String getHost() {
        if (url == null) {
            return null;
        }
        return url.getHost();
    }

    private int getPort() {
        if (url == null) {
            return -1;
        }
        return url.getPort() > 0 ? url.getPort() : 443;
    }

    @Override
    public void connect() throws IOException {
        Log.d(TAG, "connect() - host: " + getHost() + ", port: " + getPort() + ", path: " + url.getPath());
        int result = mNative.tlsOpen(
                2, //HTTP
                getHost(),
                getPort(),
                new byte[0],
                getConnectTimeout());
        if (result == -1) {
            throw new IOException("tlsOpen failed!");
        }

        connected = true;
    }

    @Override
    public void disconnect() {
        Log.d(TAG, "disconnect()");
        mNative.tlsClose();
    }

    public void shutdown() {
        Log.d(TAG, "shutdown()");
        mNative.tlsShutdown();
    }

    @Override
    public boolean usingProxy() {
        return false;
    }

    private void sendRequestHeader() throws IOException {
        Log.d(TAG, "sendRequestHeader()");

        //헤더 정보를 빌드한다.
        String headers = buildRequestHeader();
        Log.d(TAG, "sendRequestHeader() ------------ BEGIN");
        Log.d(TAG, "" + headers);
        Log.d(TAG, "sendRequestHeader() ------------ END");

        //연결한다.
        connect();

        //헤더 정보를 전송한다.
        OutputStream os = mNative.getOutputStream();
        os.write(headers.getBytes());

        return;
    }

    private String buildRequestHeader() {
        StringBuilder dump = new StringBuilder();
        try {
            //start line
            dump.append(getRequestMethod());
            dump.append(" " + url.getPath());
            if (!TextUtils.isEmpty(url.getQuery())) {
                dump.append("?" + url.getQuery());
            }
            dump.append(" " + "HTTP/1.1" + CRLF);

            //header
            dump.append("host" + ": " + getHost() + ":" + getPort() + CRLF);
            if (fixedContentLength > 0) {
                dump.append("content-length: " + fixedContentLength + CRLF);
            }
            else {
                dump.append("content-length: " + 0 + CRLF);
            }
            for (String header : getRequestProperties().keySet()) {
                if (header != null && !header.equalsIgnoreCase("content-length")) {
                    for (String value : getRequestProperties().get(header)) {
                        dump.append(header + ": " + value + CRLF);
                    }
                }
            }
            dump.append(CRLF);
        }
        catch (Exception e) {
            e.printStackTrace();
        }

        return dump.toString();
    }

    /////////////////////////////////////////////////////
    // Request
    /////////////////////////////////////////////////////
    private Map<String,List<String>> mRequestHeaderFields;
    private List<String>             mRequestHeaderList;

    @Override
    public void setRequestProperty(String key, String value) {
        if (connected)
            throw new IllegalStateException("Already connected");
        if (key == null)
            throw new NullPointerException ("key is null");

        putRequestHeaderField(key, value);
    }

    @Override
    public Map<String,List<String>> getRequestProperties() {
        if (connected)
            throw new IllegalStateException("Already connected");

        return mRequestHeaderFields;
    }

    private void putRequestHeaderField(String name, String value) {
        synchronized (mRequestHeaderFields) {
            if (!mRequestHeaderFields.containsKey(name)) {
                List<String> l = new ArrayList<>();
                l.add(value);
                mRequestHeaderFields.put(name, l);
                mRequestHeaderList  .add(name);
            }
        }
    }

    /////////////////////////////////////////////////////
    // Response
    /////////////////////////////////////////////////////
    private Map<String,List<String>> mResponseHeaderFields;
    private List<String>             mResponseHeaderList;

    @Override
    public Map<String,List<String>> getHeaderFields() {
        return mResponseHeaderFields;
    }

    private void putResponseHeaderField(String name, String value) {
        String key = name.toLowerCase();
        synchronized (mResponseHeaderFields) {
            if (!mResponseHeaderFields.containsKey(key)) {
                List<String> l = new ArrayList<>();
                l.add(value);
                mResponseHeaderFields.put(key, l);
                mResponseHeaderList  .add(key);
            }
        }
    }

    private void parse() throws IOException {
        parseStatus();
        parseHeaders();

        //Chunked Mode?
        String transferEncodingValue = getHeaderField("transfer-encoding");
        if (transferEncodingValue != null && "chunked".equalsIgnoreCase(transferEncodingValue)) {
            Log.d(TAG, "parse() - chunked mode!!");
            mIStream.setChunked(true);
        }

        String contentLengthValue = getHeaderField("content-length");
        try {
            int contentLength = Integer.parseInt(contentLengthValue);
            mIStream.setContentLength(contentLength);
        }
        catch (Exception e) { }
    }

    private void parseStatus() throws IOException {
        //Log.d(TAG, "parseStatus(enter)");

        String statusLine = mIStream.readLine();

        Log.d(TAG, "parseStatus() - statusLine: (" + statusLine + ")");
        if (statusLine.startsWith("HTTP/1.")) {
            int codePos = statusLine.indexOf(' ');
            if (codePos > 0) {

                int phrasePos = statusLine.indexOf(' ', codePos+1);
                if (phrasePos > 0 && phrasePos < statusLine.length()) {
                    responseMessage = statusLine.substring(phrasePos+1);
                }

                // deviation from RFC 2616 - don't reject status line
                // if SP Reason-Phrase is not included.
                if (phrasePos < 0)
                    phrasePos = statusLine.length();

                try {
                    responseCode = Integer.parseInt
                            (statusLine.substring(codePos+1, phrasePos));

                } catch (NumberFormatException e) { }
            }
        }
    }

    private void parseHeaders() throws IOException {
        //Log.d(TAG, "parseHeaders(enter)");

        String name = null;
        StringBuffer value = null;
        while (true) {
            String headerLine = mIStream.readLine();
            Log.d(TAG, "parseHeaders() - headerLine: (" + headerLine + ")");
            if ((headerLine == null) || (headerLine.length() == 0)) {
                break;
            }

            // Parse the header name and value
            // Check for folded headers first
            // Detect LWS-char see HTTP/1.0 or HTTP/1.1 Section 2.2
            // discussion on folded headers
            if ((headerLine.charAt(0) == ' ') || (headerLine.charAt(0) == '\t')) {
                // we have continuation folded header
                // so append value
                if (value != null) {
                    value.append(' ');
                    value.append(headerLine.trim());
                }
            } else {
                // make sure we save the previous name,value pair if present
                if (name != null) {
                    putResponseHeaderField(name, value.toString());
                }

                // Otherwise we should have normal HTTP header line
                // Parse the header name and value
                int colon = headerLine.indexOf(":");
                if (colon < 0) {
                    throw new IOException("Unable to parse header: " + headerLine);
                }
                name  = headerLine.substring(0, colon).trim();
                value = new StringBuffer(headerLine.substring(colon + 1).trim());
            }
        }

        // make sure we save the last name,value pair if present
        if (name != null) {
            putResponseHeaderField(name, value.toString());
        }

        return ;
    }

//    private int parseInt(String h) throws NumberFormatException {
//        return Integer.parseInt(h, 16);
//    }

    /////////////////////////////////////////////////////
    // InputStream
    /////////////////////////////////////////////////////
    public class TLSURLInputStream extends InputStream {
        private byte[] bytes = new byte[2048];
        private int limit = 0;

        private int     chunkRemains = -999;
        private boolean chunked;

        private int contentCompleted= 0;
        private int contentLength   = -1;

        protected void setChunked(boolean chunked) {
            this.chunked = chunked;
        }

        protected void setContentLength(int contentLength) {
            this.contentLength   = contentLength;
            this.contentCompleted= 0;
        }

        @Override
        public int read() throws IOException {
            byte[] bytes = new byte[1];
            int n = read(bytes, 0, 1);
            if (n <= 0) {
                return n;
            }
            int result = (int )(bytes[0] & 0xff);

            Log.d(TAG, "read() ... result: " + result);

            return result;
        }

        @Override
        public int read(@NonNull byte[] b, int off, int len) throws IOException {
            if (chunked) {
                return readChunk(b, off, len);
            }
            if (contentLength > 0) {
                return readContent(b, off, len);
            }
            return readBytes(b, off, len);
        }

        public int readBytes(@NonNull byte[] b, int off, int len) throws IOException {
            TLSNativeIF.TLSInputStream is = mNative.getInputStream();
            if (is == null) {
                throw new IOException("Native InputStream is NULL");
            }

            if (limit == 0) {
                //fill buffer..
                if ((limit = is.read(bytes, 0, bytes.length, getReadTimeout())) <= 0) {
                    Log.e(TAG, "readBytes() - is.read() returns ... " + limit);
                    return limit;
                }
                //Log.d(TAG, "" + HexUtil.toString(bytes, limit));
                Log.d(TAG, "readBytes() ... limit: " + limit);
            }

            //copy array..
            int n = Math.min(limit, len);
            System.arraycopy(bytes, 0, b, off, n);

            ByteBuffer buffer = ByteBuffer.wrap(bytes);
            buffer.limit(limit).position(n);
            buffer.compact();
            limit -= n;

            //copy한 길이만큼 반환한다....
            return n;
        }

        private byte[] readRawLine() throws IOException {
            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            byte[] bytes = new byte[1];
            while (readBytes(bytes, 0, 1) > 0) {
                buf.write(bytes[0]);
                if (bytes[0] == '\n') {
                    break;
                }
            }
            if (buf.size() == 0) {
                return null;
            }
            return buf.toByteArray();
        }

        private String readLine() throws IOException {
            byte[] rawdata = readRawLine();
            if (rawdata == null) {
                return null;
            }
            int len = rawdata.length;
            int offset = 0;
            if (len > 0) {
                if (rawdata[len - 1] == '\n') {
                    offset++;
                    if (len > 1) {
                        if (rawdata[len - 2] == '\r') {
                            offset++;
                        }
                    }
                }
            }
            return new String(rawdata, 0, len - offset);
        }

        private int readContent(@NonNull byte[] b, int off, int len) throws IOException {
            Log.d(TAG, "readContents() ... len: " + len
                    + ", contentLength: " + contentLength
                    + ", contentCompleted: " + contentCompleted);
            int nRead = readBytes(b, off, len);
            if (nRead <= 0) {
                if (contentLength != contentCompleted) {
                    throw new IOException("contents imcompleted!");
                }
            }
            contentCompleted += nRead;

            return nRead;
        }

        private int readChunk(@NonNull byte[] b, int off, int len) throws IOException {
            Log.d(TAG, "readChunk() ... len: " + len + ", oldChunkRemains: " + chunkRemains);

            if (chunkRemains == 0 || chunkRemains == -999) {
                chunkRemains = getChunkSize(chunkRemains == 0 ? true : false);
                Log.d(TAG, "readChunk() - newChunkRemains: " + chunkRemains);
                //error
                if (chunkRemains == -1) {
                    throw new IOException("readChunk->getChunkSize() returns .... -1");
                }
                //eof
                else if (chunkRemains == 0) {
                    Log.d(TAG, "readChunk() meets EOF!");
                    return -1; //EOF를 의미
                }
            }

            int minSize = Math.min(chunkRemains, len);
            int nRead   = readBytes(b, off, minSize);
            Log.d(TAG, "readChunk() - chunkRemains: " + chunkRemains
                    + ", len: " + len
                    + ", minSize: " + minSize
                    + ", nRead: " + nRead);
            if (nRead == -1) {
                throw new IOException("readChunk->readBytes() returns .... -1");
            }
            chunkRemains -= nRead;

            return nRead;
        }

        private int getChunkSize(boolean skipFlag) {
            Log.d(TAG, "getChunkSize() ... skipFlag: " + skipFlag);

            try {
                if (skipFlag) {
                    byte[] cr = new byte[1];
                    byte[] lf = new byte[1];
                    readBytes(cr, 0, 1);
                    readBytes(lf, 0, 1);
                    if (cr[0] != '\r' || lf[0] != '\n') {
                        Log.e(TAG, "CRLF expected at end of chunk");
                        return -1;
                    }
                }

                //parse data
                String chunkLine = readLine();
                if ((chunkLine == null) || (chunkLine.length() == 0)) {
                    return -1; //EOF?
                }

                int separator = chunkLine.indexOf(';');
                if (separator < 0) {
                    separator = chunkLine.length();
                }

                return Integer.parseInt(chunkLine.substring(0, separator).trim(), 16);
            }
            catch (Exception e) {
                e.printStackTrace();
            }

            return -1;
        }
    };

}
