package com.kodeholic.httpswithopenssl.lib.http;

import android.annotation.SuppressLint;
import android.content.Context;
import android.os.Build;

import com.kodeholic.httpswithopenssl.lib.util.EReason;
import com.kodeholic.httpswithopenssl.lib.util.Log;
import com.kodeholic.httpswithopenssl.lib.util.MimeUtil;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Timer;
import java.util.TimerTask;
import java.util.UUID;
import java.util.zip.GZIPInputStream;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

public class HttpUtil {
	public static final String LOG_TAG = "HttpUtil";

	public static final int STEP_INIT    = 0;
	public static final int STEP_CONNECT = 1;
	public static final int STEP_REQUEST = 2;
	public static final int STEP_RESPONSE= 3;
	
	private final static int     HTTP_NOT_ACCESSIBLE = 599;
	private final static String  CRLF = "\r\n";
	private final static String  SecureLock = "SecureLock";
	private       static boolean SecureInited = false;

	private Context             mContext = null;
	private String              mHttpPath;
	private Map<String, String> mHttpRequestHeader;
	private Map<String, Iterable<String>> mHttpResponseHeader;
	private Param               mParam;
	
	/* for response */
	private int     responseCode;
	private String  responseMesg    = null;
	private String  responseContent = null;
	private String  responseCType   = null;
	private String  responseCharset = null;

	/* for extra (should be reset) */
	private HttpURLConnection mHttpConn   = null;
	private HttpCancel        mHttpCancel = null;
	private int               mHttpStep   = 0;
	private int               mHttpSequence = 0;
	private List<String>      mVerifiedHosts = null;
	
	public HttpUtil(Context context) {
		this.mContext    = context;
		this.mHttpPath   = "";
		this.mHttpRequestHeader  = new HashMap<String, String>();
		this.mHttpResponseHeader = new HashMap<String, Iterable<String>>();
		this.mHttpCancel = new HttpCancel();
		this.mParam      = new Param();
		
		this.prepare();
	}
	
	public Context getContext() { return mContext; }
	public HttpURLConnection getURLConnection() {
		return mHttpConn;
	}
	public void cancel() { mHttpCancel.cancel(); }
	private void prepare() {
		this.mHttpConn        = null;
		this.responseContent = null;
		this.responseCode    = HTTP_NOT_ACCESSIBLE;
		this.updateStep(STEP_INIT);
	}
	
	private void updateStep(int step) {
		this.mHttpStep = step;
	}
	
	public int getHttpStep() {
		return this.mHttpStep;
	}
	
	public void setHttpSequence(int httpSequence) {
		this.mHttpSequence = httpSequence;
	}

	public Param getParam() {
		return mParam;
	}
	
	private static void unused1_setDefaultSSLSocketFactory() {
		synchronized (SecureLock) {
			if (SecureInited) {
				Log.i(LOG_TAG, "DefaultSSLSocketFactory Already Initialized.");
				return;
			}

            TrustManager[] trustManager = null;
            TrustManager[] wrappedTrustManagers = null;

            if (Build.VERSION.SDK_INT > Build.VERSION_CODES.KITKAT) {
                TrustManagerFactory tmf = null;
                try {
                    tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                } catch (NoSuchAlgorithmException e1) {
                    // TODO Auto-generated catch block
                    e1.printStackTrace();
                }
                try {
                    tmf.init((KeyStore)null);
                } catch (KeyStoreException e1) {
                    // TODO Auto-generated catch block
                    e1.printStackTrace();
                }

                TrustManager[] trustManagers = tmf.getTrustManagers();
                final X509TrustManager origTrustmanager = (X509TrustManager)trustManagers[0];

                wrappedTrustManagers = new TrustManager[] {
                        new X509TrustManager() {
                            public X509Certificate[] getAcceptedIssuers() {
                                return origTrustmanager.getAcceptedIssuers();
                            }

                            public void checkClientTrusted(X509Certificate[] certs, String authType) {
                                try {
                                    origTrustmanager.checkClientTrusted(certs, authType);
                                } catch (CertificateException e) {
                                    // TODO Auto-generated catch block
                                    e.printStackTrace();
                                }
                            }

                            public void checkServerTrusted(X509Certificate[] certs, String authType) {
                                try {
                                    origTrustmanager.checkServerTrusted(certs, authType);
                                } catch (CertificateException e) {
                                    // TODO Auto-generated catch block
                                    e.printStackTrace();
                                }
                            }
                        }
                };
            } else {
            	trustManager= new TrustManager [] { };
            }

			try {
				SSLContext sslContext= SSLContext.getInstance("TLS");
				if(Build.VERSION.SDK_INT > Build.VERSION_CODES.KITKAT) {
                    sslContext.init(null, wrappedTrustManagers, new SecureRandom());
                } else {
                	sslContext.init(null, trustManager, new SecureRandom());
                }
				HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());

				Log.i(LOG_TAG, "DefaultSSLSocketFactory Initialized At This Time.");
				SecureInited = true;
			}
			catch (Exception e) { Log.e(LOG_TAG, "Fail to setDefaultSSLSocketFactory()", e);
			}
		}
	}
	
	private static void setDefaultSSLSocketFactory() {
		synchronized (SecureLock) {
			if (SecureInited) {
				Log.i(LOG_TAG, "DefaultSSLSocketFactory Already Initialized.");
				return;
			}

			try { 
				SSLContext sslContext= SSLContext.getInstance("TLS");
				
				sslContext.init(null, new X509TrustManager[]{ new X509TrustManager(){

			        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {}

			        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {}

			        public X509Certificate[] getAcceptedIssuers() {

			            return new X509Certificate[0];

			        }

			    }}, new SecureRandom());

				HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory()); 

				Log.i(LOG_TAG, "DefaultSSLSocketFactory Initialized At This Time.");
				SecureInited = true;
			} 
			catch (Exception e) { 
				Log.e(LOG_TAG, "Fail to setDefaultSSLSocketFactory()", e); 
			}
		}
	}

	public void clear() {
		if (this.mHttpRequestHeader  != null) this.mHttpRequestHeader .clear();
		if (this.mHttpResponseHeader != null) this.mHttpResponseHeader.clear();
		if (this.mParam != null) this.mParam.clear();
		this.mHttpRequestHeader = null;
	}
	
	public void putPath(String path) {
		this.mHttpPath += path;
	}
	
	public void putHeader(String key, String value) {
		this.mHttpRequestHeader.put(key, value);
	}
	
	public void putMultipart(String name, File file) throws Exception {
		String fileName = null;
		int index = file.getName().lastIndexOf(".");
		if (index != -1) {
			fileName = UUIDUtil.next(1) + file.getName().substring(index);
		}
		else {
			fileName = System.currentTimeMillis() + "_" + file.getName();			
		}		
		
		this.mParam.getMultiparts().add(new Media(name, file, fileName));
	}
	
	public void putMultipart(String text) throws Exception {
		this.mParam.getMultiparts().add(new Plain(text));
	}
	
	public void putBody(String body) {
		this.mParam.setBody(body);
	}
	
	public void putOutFile(File file, boolean append) {
		this.mParam.setOutFile(file, append);
	}
	
	public String getResponseContent() {
		return (this.responseContent != null) ? this.responseContent : "";
	}
	
	public int getResponseCode() {
		return this.responseCode;
	}
	
	public String getResponseCharset() {
		return this.responseCharset;
	}
	
	private String splitCharset(String s) {
		if (s == null) { return null; }
		
		//
		try {
			String   charset = null;
			String[] values  = s.split(";"); //The values.length must be equal to 2...
	
			for (String value : values) {
			    value = value.trim();
			    if (value.toLowerCase().startsWith("charset=")) {
			        charset = value.substring("charset=".length());
			        break;
			    }
			}
			
			return charset;
		}
		catch (Exception e) { e.printStackTrace();
		}
		
		return null;
	}
	
	private URL pathToURL() throws Exception {
		URL url = new URL(mHttpPath);
		/*
		URI uri = new URI(
				url.getProtocol(), 
				url.getUserInfo(), 
				url.getHost(), 
				url.getPort(), 
				url.getPath(), 
				url.getQuery(), 
				url.getRef());
		
		return uri.toURL();
		*/
		
		return url;
	}
	
	private String dumpRequest(HttpURLConnection conn) {
		StringBuilder dump = new StringBuilder();
		try {
			/* start line (*/
			dump.append(mParam.getMethod()   + " ");
			dump.append(pathToURL() + " ");
			dump.append("HTTP/1.1" + CRLF);
			
			/* header */
			for (String header : conn.getRequestProperties().keySet()) {
				if (header != null) {
					for (String value : conn.getRequestProperties().get(header)) {
						dump.append(header + ":" + value + CRLF);
					}
				}
			}
			dump.append(CRLF);
			
			/* body */
			if (mParam.hasMultipart()) {
				for (Multipart multipart : mParam.getMultiparts()) {
					dump.append(new String(multipart.getDisposition(), "UTF-8"));
					if (multipart.getText() != null) dump.append(new String(multipart.getText(), "UTF-8"));
					else                             dump.append("(...)");
					dump.append(CRLF);
				}
				dump.append(new String(mParam.getLastDisposition(), "UTF-8"));
			}
			else if (mParam.getBody() != null){
				dump.append(mParam.getBody());
			}			
		}
		catch (Exception ignore) { ;
		}

		return dump.toString();
	}
	
	private String dumpResponse(HttpURLConnection conn) {
		StringBuilder dump = new StringBuilder();
		
		try {
			/* status line (*/
			dump.append("HTTP/1.1" + " ");
			dump.append(this.responseCode + " ");
			dump.append(this.responseMesg + CRLF);
	
			/* header */
			int    i = 0;
			String key;
			while ((key = conn.getHeaderFieldKey(i)) != null) {
				String value = conn.getHeaderField(i);
				dump.append(key + ":" + value + CRLF);
				i++;
			}
			if (mParam.getOutFile() != null || mParam.getBaoStream() != null) {
				dump.append(CRLF);
				dump.append("(...)");
			}
			else if (responseContent != null && responseContent.length() != 0) {
				dump.append(CRLF);
				if (responseContent.length() >= 128 * 1024) {
					dump.append("(Too long!)");
				}
				else {
					dump.append(responseContent);
				}
			}
		}
		catch (Exception ignore) { ; }
		
		return dump.toString();
	}
	
	public Map<String, Iterable<String>> getHttpResponseHeader() {
		return mHttpResponseHeader;
	}

	public Iterable<String> getResponseHeaderField(String name) {
		if (name != null) {
			Iterable<String> values = null;
			if ((values = mHttpResponseHeader.get(name)) != null) {
				return values;
			}
			if ((values = mHttpResponseHeader.get(name.toLowerCase())) != null) {
				return values;
			}
			if ((values = mHttpResponseHeader.get(name.toUpperCase())) != null) {
				return values;
			}
		}

		return null;
	}
	
	private Map<String, Iterable<String>> copyHttpResponseHeader(HttpURLConnection conn) {
//		String key;
//		int i = 0;
//		while ((key = conn.getHeaderFieldKey(i)) != null) {
//			mHttpResponseHeader.put(key, conn.getHeaderField(i));
//			i++;
//		}

		mHttpResponseHeader.putAll(conn.getHeaderFields());
		return mHttpResponseHeader;
	}
	
	@SuppressLint("DefaultLocale")
	private HttpURLConnection getHttpURLConnection(URL url) throws Exception {
		//System.setProperty("http.keepAlive", "false");
		// HTTP
		if (!url.getProtocol().toUpperCase().contains("HTTPS")) {
			return (HttpURLConnection)url.openConnection();
		}

		return new TLSURLConnection(mContext, url);
	}
	
	private HttpURLConnection createConnection() throws Exception {
		try {			
			HttpURLConnection conn = null;
			
			conn = getHttpURLConnection(pathToURL());
			conn.setRequestMethod (mParam.getMethod());
			if (mParam.getConnectTimeo() > 0) {
				conn.setConnectTimeout(mParam.getConnectTimeo());
			}
			if (mParam.getExecTimeo() > 0) {
				conn.setReadTimeout(mParam.getExecTimeo() > 30000 ? 30000 : mParam.getExecTimeo());
			}
			// cache-control
			conn.setUseCaches      (false);
			conn.setRequestProperty("cache-control", "no-cache");
			// connection-control
			conn.setRequestProperty("connection", "close");
			
			return conn;
		}
		catch (Exception e) {
			try {
				if (mHttpConn != null) { mHttpConn.disconnect(); }
			}
			catch (Exception ignore) { ; }
			
			throw e;
		}
	}
	
	private void writeSinglePart() throws SocketTimeoutException, Exception {
		// prepare header
		for (Map.Entry<String, String> ent : mHttpRequestHeader.entrySet()) {
			mHttpConn.setRequestProperty(ent.getKey(), ent.getValue());
		}
		
		DataOutputStream outStream = null;
		try {
			if (mParam.getContents() == null) {
				Log.v(LOG_TAG, "============================================\n" + dumpRequest(mHttpConn));
				return;
			}
			mHttpConn.setRequestProperty("content-type", "application/json;charset=UTF-8");
			mHttpConn.setRequestProperty("content-length", mParam.getTotalBytes() + "");
			Log.v(LOG_TAG, "============================================\n" + dumpRequest(mHttpConn));
				
			mHttpConn.setDoOutput(true);
			mHttpConn.setFixedLengthStreamingMode(mParam.getTotalBytes());
			outStream = new DataOutputStream(mHttpConn.getOutputStream());
			outStream.write(mParam.getContents());			
			outStream.flush();
			mParam.progress(false);
		}
		finally {
			try {
				if (outStream != null) outStream.close();
			}
			catch (Exception ignore) { ; }
		}
	}
	
	private void writeMultiPart() throws SocketTimeoutException, Exception {
		mHttpConn.setRequestProperty("content-type" , 
				"multipart/form-data;" +
				"charset=utf-8;" +
				"boundary=" + mParam.getBoundary());
		for (Map.Entry<String, String> ent : mHttpRequestHeader.entrySet()) {
			mHttpConn.setRequestProperty(ent.getKey(), ent.getValue());
		}
		Log.v(LOG_TAG, "============================================\n" + dumpRequest(mHttpConn));

		//DataOutputStream outStream = null;	
		OutputStream outStream = null;	
		try {
			/* content-length */
			/* httpConn.setRequestProperty("content-length", param.getTotalBytes() + ""); */
			mHttpConn.setDoOutput (true );
			mHttpConn.setFixedLengthStreamingMode(mParam.getTotalBytes());
			outStream = mHttpConn.getOutputStream();
			for (Multipart multipart : mParam.getMultiparts()) {
				writeMedia(outStream, multipart);
			}
			outStream.write(mParam.getLastDisposition());
			outStream.flush();
			mParam.progress(false);
		}
		finally {
			try {
				if (outStream != null) outStream.close();
			}
			catch (Exception ignore) { ; }
		}
	}
	
	private void writeMedia(OutputStream outStream, Multipart multipart) throws Exception {
		/* write disposition */
		outStream.write(multipart.getDisposition());
		
		/* write media */
		FileInputStream inStream = null;
		try {
			/* write Contents */
			if (multipart.getFile() != null) {
				inStream = new FileInputStream(multipart.getFile());
				int bufferSize = Math.min(inStream.available(), 8192);
				byte[] buffer  = new byte[bufferSize];
				int    nBytes  = 0;
				while ((nBytes = inStream.read(buffer, 0, bufferSize)) > 0) {
					//Log.d(LOG_TAG, "[PAUSED] after read - " + nBytes);
					outStream.write(buffer, 0, nBytes);
					//Log.d(LOG_TAG, "[PAUSED] after write - " + nBytes);
					mParam.progress(nBytes, false, false);
				}
			}
			else if (multipart.getText() != null) {
				outStream.write(multipart.getText());
				mParam.progress(multipart.getSize(), false, false);
			}
			outStream.write(CRLF.getBytes("UTF-8"));
		}
		finally {
			try {
				if (inStream != null) inStream.close();
			}
			catch (Exception ignore) { ; }
		}
	}
	
	private InputStream getInputStream(HttpURLConnection httpConn) throws Exception {
		InputStream inStream = null;
		

//		/* check Stream */
//		try{
//			responseCode   = httpConn.getResponseCode();
//		}
//		catch (Exception e){
//			e.printStackTrace();
//			
//			if (e.getMessage().contains("authentication challenge")) {
//		        responseCode = HttpsURLConnection.HTTP_UNAUTHORIZED;
//		        Log.d(LOG_TAG, "Exception. 401:" + e.getMessage());
//		        
//		        inStream = httpConn.getErrorStream();
//				return inStream;    
//		        
//		    } else { throw e; }
//		}
		try {
			/* for 401 case: call getResponseCode() two times  */
			try {
				responseCode = httpConn.getResponseCode();
			}
			catch (IOException e) { e.printStackTrace();		
			}			
			responseCode   = httpConn.getResponseCode();
			responseMesg   = httpConn.getResponseMessage();
			responseCType  = httpConn.getContentType();
			responseCharset= splitCharset(responseCType);
			copyHttpResponseHeader(httpConn);
			
			mParam.setTotalBytes(httpConn.getContentLength());
			if (responseCode >= HttpURLConnection.HTTP_OK 
					&& responseCode <= HttpURLConnection.HTTP_ACCEPTED)
			{
				inStream = httpConn.getInputStream();
			}
			else { 
				inStream = httpConn.getErrorStream();
			}
			
			/* check Encoding */
			String encoding = httpConn.getHeaderField("Content-Encoding");
			if (encoding != null && encoding.trim().compareToIgnoreCase("gzip") == 0) {
				Log.d(LOG_TAG, "encoding: " + encoding);
				return new GZIPInputStream(inStream);
			}
			
			return inStream;
		}
		catch (Exception e) {
			try {
				if (inStream != null) inStream.close();
			}
			catch (Exception ignore) { ; }
			
			//
			throw e;
		}
	}
	
	private void readFromInput(File outPath, boolean append) throws Exception {
		InputStream      inStream  = null;
		FileOutputStream outStream = null;
		try {
			this.responseCode = HTTP_NOT_ACCESSIBLE;
			//
			if ( outPath != null) { outStream = new FileOutputStream(outPath, append); }
			if ((inStream = getInputStream(mHttpConn)) != null) {
				String charSet = "UTF-8";
				if (responseCharset != null && !"UTF-8".equalsIgnoreCase(responseCharset)) {
					charSet = responseCharset;
				}
				
				//
				ByteArrayOutputStream response = mParam.getBaoStream();
				if (response == null) {
					response = new ByteArrayOutputStream();
				}
				byte[] buffer  = new byte[8192];
				int    nBytes = 0;
				while ((nBytes = inStream.read(buffer, 0, buffer.length)) > 0) {
					if (outStream != null) { outStream.write(buffer, 0, nBytes); }
					else                   { response.write(buffer, 0, nBytes); }
					mParam.progress(nBytes, true, false);
				}
				if (outPath != null || mParam.getBaoStream() != null) {
					this.responseContent = "";
				}
				else {
					this.responseContent = new String(response.toByteArray(), 0, response.size(), charSet);
				}
			}
			mParam.progress(true);
		}
		finally {
			if (inStream != null) {
				try {
					inStream.close();
				}
				catch (Exception ignore) { ; }
			}
			if (outStream != null) {
				try {
					outStream.close();
				}
				catch (Exception ignore) { ; }
			}
		}
	}

	private int execute(int currTries, int maxTries) {
		Log.d(LOG_TAG, "[" + mHttpSequence + "]EXECUTE STARTED " + mHttpPath + " (" + currTries + " / " + maxTries + ")");

		HttpTimer httpTimer = new HttpTimer();
		if (mParam.getExecTimeo() > 0) {
			httpTimer.start(mParam.getExecTimeo());
		}
		try {
			this.updateStep(STEP_CONNECT);
			this.mHttpConn = createConnection();
			
			this.updateStep(STEP_REQUEST);
			if (mParam.hasMultipart()) { writeMultiPart (); }				
			else                       { writeSinglePart(); }

			this.updateStep(STEP_RESPONSE);
			readFromInput(mParam.getOutFile(), mParam.isAppend());
			
			/* dump */
			Log.v(LOG_TAG, "--------------------------------------------\n" + dumpResponse(mHttpConn));
			Log.d(LOG_TAG, "[" + mHttpSequence + "]EXECUTE STOPPED " + mHttpPath);
		}
		catch (SocketTimeoutException ste) {
			Log.e(LOG_TAG, "[" + mHttpSequence + "]EXECUTE FAILED1 " + mHttpPath, ste);
			return EReason.I_ECONNTIMEO;
		}	
		catch (Exception e) {
			Log.e(LOG_TAG, "[" + mHttpSequence + "]EXECUTE FAILED2 " + mHttpPath, e);
			if (httpTimer.isInterrupted()) {
				return EReason.I_EEXECTIMEO;
			}
			if (mHttpCancel.isCanceled()) {
				return EReason.I_ECANCELED;
			}
			
			return EReason.I_EIO;
		}
		finally {
			if (mHttpConn != null) { mHttpConn.disconnect(); mHttpConn = null; }
			if (httpTimer != null) { httpTimer.stop(); }
		}
			
		return EReason.I_EOK;
	}
	
	private int execute() {
		int cc = EReason.I_EPREPARE;
		try {
			int currTries = 0;
			int maxTries  = mParam.getMaxTries();
			if (maxTries <= 0) {
				maxTries  = 1;
			}
			while (true) {
				currTries += 1;
				this.prepare();
				mParam.prepare();
				cc = execute(currTries, maxTries);
				if (cc == EReason.I_EOK
						|| cc == EReason.I_ECANCELED) 
				{
					break;
				}
				if (currTries >= maxTries) {
					break;
				}
				synchronized (this) {
					try {
						this.wait(2 * 1000);
					}
					catch (InterruptedException ignore) { ; }
				}
			}
		}
		catch (Exception e) { e.printStackTrace();
		}
		
		return cc;
	}
	
	/* -- GET */
	public int get() {
		try {
			mParam.setMethod(Method.GET);
			mParam.setDownloading(true);
			
			return execute();
		}
		catch (Exception e) { e.printStackTrace();
		}
		
		return EReason.I_EPREPARE;
	}
	
	/* -- POST */
	public int post() {
		try {
			if (mParam.getMultiparts().size() > 0) {
				mParam.setBoundary(UUIDUtil.random());
			}
			mParam.setMethod(Method.POST);
			mParam.setDownloading(false);
			
			return execute();
		}
		catch (Exception e) { e.printStackTrace();
		}		
		
		return EReason.I_EPREPARE;
	}
	
	/* -- PUT */
	public int put() {
		try {
			if (mParam.getMultiparts().size() > 0) {
				mParam.setBoundary(UUIDUtil.random());
			}
			mParam.setMethod(Method.PUT);
			mParam.setDownloading(false);
			
			return execute();
		}
		catch (Exception e) { e.printStackTrace();
		}
		
		return EReason.I_EPREPARE;
	}	
	
	/* -- DELETE */
	public int delete() {
		try {
			mParam.setMethod(Method.DELETE);
			
			return this.execute();
		}
		catch (Exception e) { e.printStackTrace();
		}
		
		return EReason.I_EPREPARE;
	}

	/* download bytes */
	public byte[] loadThumbnail() {
		try {
			mParam.setMethod(Method.GET);
			mParam.setDownloading(true);

			int result = execute();

			if (result == EReason.I_EOK
					&& responseCode == 200
					&& mParam.getBaoStream() != null
					&& mParam.getBaoStream().size() > 0)
			{
				return mParam.getBaoStream().toByteArray();
			}
		}
		catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}
	
	public class Param {
		public static final int CONN_TIMEO = 10 * 1000;
		public static final int EXEC_TIMEO = 15 * 1000;
		public static final int MAX_TRIES  =  2;
		
		private String method;
		private String boundary;
		private String body;
		private byte[] contents;
		private byte[] lastDisposition;
		private File    outFile;
		private boolean appendFlag;
		private ByteArrayOutputStream baoStream;
		private List<Multipart> multiparts;
		
		private int  connTimeo;
		private int  execTimeo;
		private int  maxTries;
		
		private int          totalBytes;
		private int          currentBytes;
		private int          httpSequence;
		private HttpListener listener;
		private long         lastProgressTime;
		private boolean      downloading;
		
		public Param() {
			this.multiparts = new ArrayList<Multipart>();
			this.connTimeo  = CONN_TIMEO;
			this.execTimeo  = EXEC_TIMEO;
			this.maxTries   = MAX_TRIES;
			
			this.reset();
		}
		
		public void reset() {
			this.currentBytes     = 0;
			this.totalBytes       = 0;
			this.lastProgressTime = 0;
		}
		
		public void clear() {
			if (this.multiparts != null) multiparts.clear();
		}		
		public int getConnectTimeo() {
			return connTimeo;
		}
		public void setConnectTimeo(int connectTimeo) {
			this.connTimeo = connectTimeo;
		}
		public int getExecTimeo() {
			return execTimeo;
		}
		public void setExecTimeo(int execTimeo) {
			this.execTimeo = execTimeo;
		}
		public String getMethod() {
			return method;
		}
		public void setMethod(String method) {
			this.method = method;
		}
		public String getBoundary() {
			return boundary;
		}
		public void setBoundary(String boundary) {
			this.boundary = boundary;
		}
		public String getBody() {
			return body;
		}
		public void setBody(String body) {
			this.body = body;
		}
		public File getOutFile() {
			return outFile;
		}
		public void setOutFile(File output, boolean appendFlag) {
			this.outFile = output;
			this.appendFlag = appendFlag;
		}

		public boolean isAppend() {
			return appendFlag;
		}

		public ByteArrayOutputStream getBaoStream() { return baoStream; }
		public void setBaoStream(ByteArrayOutputStream baoStream) {
			this.baoStream = baoStream;
		}
		public void setListener(int httpSequence, HttpListener listener) {
			this.httpSequence = httpSequence;
			this.listener     = listener;
		}
		public boolean hasMultipart() {
			return (boundary != null) ? true : false;
		}
		public byte[] getContents() {
			return contents;
		}
		public List<Multipart> getMultiparts() {
			return multiparts;
		}
		public int getTotalBytes() {
			return totalBytes;
		}
		public void setTotalBytes(int totalBytes) {
			this.totalBytes = totalBytes;
		}		
		public int getMaxTries() {
			return maxTries;
		}
		public void setMaxTries(int maxTries) {
			this.maxTries = maxTries;
		}
		public void setDownloading(boolean downloading) {
			this.downloading = downloading;
		}
		public boolean isDownloading() {
			return downloading;
		}
		public void progress(boolean isDownloading) {
			progress(totalBytes, isDownloading, true);
		}
		public void progress(int nBytes, boolean isDownloading, boolean flushFlag) {
			if (nBytes <= 0) {
				return;
			}
			if ((currentBytes += nBytes) > totalBytes) {
				currentBytes = totalBytes;
			}
			if (listener != null && this.downloading == isDownloading) {
				long current = System.currentTimeMillis() / 100;
				if (flushFlag || current != lastProgressTime) {
					Log.v(LOG_TAG, (isDownloading ? "downloading" : "uploading") + ".... " + currentBytes + " / " + totalBytes);
					listener.onProgress(httpSequence, currentBytes, totalBytes);
					lastProgressTime = current;
				}
			}
			
			return;
		}
		
		public byte[] getLastDisposition() {
			return lastDisposition;
		}
		
		private byte[] createLastDisposition() throws Exception {
			return ("--" + mParam.getBoundary() + "--").getBytes("UTF-8");
		}
		
		public void prepare() throws Exception {
			totalBytes      = 0;
			currentBytes    = 0;
			lastDisposition = createLastDisposition();
			
			if (body     != null) { contents   = body.getBytes("UTF-8"); }			
			if (contents != null) { totalBytes = contents.length; }
			else {
				for (Multipart multipart : multiparts) {
					multipart.prepare(getBoundary());
					totalBytes += multipart.getSize();
				}
				if (hasMultipart()) {
					totalBytes += lastDisposition.length;
				}
			}
			
			return;
		}
	}
	
	public interface Multipart {
		public String getName();
		public byte[] getText();
		public File   getFile();
		public String getFileName();
		public int    getSize();
		public byte[] getDisposition();
		public void   prepare(String boundary) throws Exception;
	}
	
	public class Media implements Multipart {
		private String name;
		private File   file;
		private String fileName;
		private String mimeType;
		private byte[] disposition;
		
		public Media(String name, File file, String fileName) throws Exception {
			this.name = name;
			this.file = file;
			this.fileName = fileName;
			this.mimeType = MimeUtil.getMimeTypeFromFile(file.getName());
		}
		
		@Override
		public String getName() { return name; }
		
		@Override
		public File getFile() { return file; }

		@Override
		public String getFileName() { return fileName; }

		@Override
		public int getSize() { 
			return disposition.length + (int)file.length() + CRLF.length();
		}

		@Override
		public byte[] getText() { return null; }

		@Override
		public byte[] getDisposition() { return disposition; }

		@Override
		public void prepare(String boundary) throws Exception {
			StringBuilder sb = new StringBuilder();
			sb.append("--" + boundary + CRLF);
			sb.append("content-disposition: form-data;name=\"" + name + "\"; filename=\"" + fileName + "\"" + CRLF);
			sb.append("content-type: " + mimeType + CRLF);
			sb.append(CRLF);
			disposition = sb.toString().getBytes("UTF-8");
		}
	}
	
	public class Plain implements Multipart {
		private String name;
		private byte[] text;
		private byte[] disposition;
		private String mimeType;

		public Plain(String text) throws Exception {
			this("meta-data", text);
		}
		public Plain(String name, String text) throws Exception {
			this.name = name;
			this.text = text.getBytes("UTF-8");
			this.mimeType = "application/json";
		}
		
		@Override
		public String getName() { return name; }
		
		@Override
		public byte[] getText() { return text; }
		
		@Override
		public int getSize() { 
			return disposition.length + text.length + CRLF.length();
		}

		@Override
		public String getFileName() { return ""; }
		
		@Override
		public File getFile() { return null; }

		@Override
		public byte[] getDisposition() { return disposition; }
		
		@Override
		public void prepare(String boundary) throws Exception {
			StringBuilder sb = new StringBuilder();
			sb.append("--" + mParam.getBoundary() + CRLF);
			sb.append("content-disposition: form-data;name=\"" + name + "\"" + CRLF);
			sb.append("content-type: " + mimeType + ";charset=utf-8" + CRLF);
			sb.append(CRLF);
			disposition = sb.toString().getBytes("UTF-8");
			
			return;
		}
	}
	
	public class HttpTimer extends Timer {
		private Timer   timer;
		private boolean interrupted;
		
		public HttpTimer() {
			this.timer      = new Timer();
			this.interrupted= false;
		}		
		public void start(long timeo) { timer.schedule(task, timeo); /*Log.d(LOG_TAG, "HttpTimer Started(" + timeo + ")");*/ }
		public void stop ()           { timer.cancel  (           ); /*Log.d(LOG_TAG, "HttpTimer Stopped");               */ }
		public boolean isInterrupted() {
			return interrupted;
		}
		
		private TimerTask task = new TimerTask() {
			@Override
			public void run() {
				Log.d(LOG_TAG, "Timer Interrupted");
				interrupted = true;
				shutdown(mHttpConn, "HttpTimer");
			}
		};
	}
	
	public class HttpCancel {
		private boolean canceled;
		
		public HttpCancel() {
			this.canceled = false;
		}
		
		public synchronized boolean isCanceled() {
			return this.canceled;
		}

		public synchronized void cancel() {
			if (!this.canceled && mHttpConn != null) {
				Log.i(LOG_TAG, "Canceling......");
				Thread t = new Thread(new Runnable() {
					@Override
					public void run() {
						shutdown(mHttpConn, "HttpCancel");
					}
				});
				t.start();
			}
			this.canceled = true;
		}
	}

	private void shutdown(HttpURLConnection httpConn, String f) {
		Log.d(LOG_TAG, "shutdown() - f: " + f + ", httpConn: " + httpConn);
		if (httpConn != null) {
			try {
				mHttpConn.getInputStream().reset();
			}
			catch (Exception e) { e.printStackTrace();
			}

			try {
				mHttpConn.getInputStream().close();
			}
			catch (Exception e) { e.printStackTrace();
			}

			try {
				mHttpConn.disconnect();
			}
			catch (Exception e) { e.printStackTrace();
			}
		}
	}
	
//	public Bitmap getBitmapFromURL() {
//		try { 
//			HttpURLConnection connection = (HttpURLConnection)url.openConnection();        
//			connection.setDoInput(true);        
//			connection.connect();        
//			InputStream input = connection.getInputStream();        
//			Bitmap myBitmap   = BitmapFactory.decodeStream(input);  
//			
//			return myBitmap;    
//		} 
//		catch (IOException e) { e.printStackTrace(); return null;    
//		}
	// }

	public static class Method {
		public static final String GET    = "GET";
		public static final String POST   = "POST";
		public static final String PUT    = "PUT";
		public static final String DELETE = "DELETE";
	}

	public static class UUIDUtil {
		private static String trim(String s) {
			return s.replace("-", "");
		}
		public static String next(int prefix) {
			UUID uuid = UUID.randomUUID();
			return trim(String.format("%08x", prefix) + uuid.toString());
		}

		public static String random() {
			UUID uuid = UUID.randomUUID();
			return trim(uuid.toString());
		}
	}
}


