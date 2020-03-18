package com.kodeholic.httpswithopenssl.lib.http;

import android.content.Context;

import java.util.ArrayList;
import java.util.List;

public abstract class HttpInvoker {
	public static final String LOG_TAG = HttpInvoker.class.getSimpleName();
	protected Context      mContext;
	protected int          mStep;
	protected TunningParam mTunningParam;
	protected boolean      mCheckLocalId = true;
	
	protected List<RequestPair> mRequestPairMap;
	
	public HttpInvoker(Context context) {
		this.mContext  = context;
		this.mStep     = -1;
		this.mTunningParam   = new TunningParam(0, 0, 0);
		this.mRequestPairMap = new ArrayList<RequestPair>();
	}
	
	public HttpInvoker(Context context, boolean checkLocalId) {
		this(context);
		mCheckLocalId = checkLocalId;
	}
	
	public Context getContext() {
		return mContext;
	}
	
	private synchronized void put(RequestPair requestPair) {
		mRequestPairMap.add(requestPair);
	}
	
	private synchronized RequestPair get(int httpSequence, boolean removeFlag) {
		for (int i = 0; i < mRequestPairMap.size(); i++) {
			RequestPair requestPair = mRequestPairMap.get(i);
			if (requestPair.getSequence() == httpSequence) {
				if (removeFlag) {
					mRequestPairMap.remove(i);
				}
				
				return requestPair;
			}
		}
		
		return null;
	}
	
	public TunningParam getTunningParam() {
		return mTunningParam;
	}
	
	private void copyTunningParam(HttpUtil.Param param) {
		if (mTunningParam.getConnectTimeo() > 0) { param.setConnectTimeo(mTunningParam.getConnectTimeo()); }
		if (mTunningParam.getExecTimeo()    > 0) { param.setExecTimeo   (mTunningParam.getExecTimeo()   ); }
		if (mTunningParam.getMaxTries()     > 0) { param.setMaxTries    (mTunningParam.getMaxTries()    ); }
	}
	
	public synchronized void onComplete(int httpSequence, int httpReason, HttpResponse httpResponse) {
		//HttpListener
		try {
			RequestPair requestPair = get(httpSequence, true);
			if (requestPair != null) {
				//invokeType for Response
				httpResponse.setInvokeType(requestPair.getInvokeType());
				httpResponse.setHttpReason(httpReason);
				if (requestPair.getListener() != null) {
					requestPair.getListener().onResponse(httpSequence, httpReason, httpResponse);
				}
			}
		}
		catch (Exception e) { e.printStackTrace();
		}

		return;
	}

	public synchronized int invoke(int invokeType, HttpRequest httpRequest, HttpListener httpListener) {
		//
//		if (mCheckLocalId && mSettings.getLocalId() == -1) {
//			Log.e(LOG_TAG, "Invalid LocalId........");
//			if (httpListener != null) {
//				HttpResponse errorResponse = new HttpResponse(EReason.I_ELOCALID);
//				errorResponse.setInvokeType(invokeType);
//				httpListener.onResponse(-1, EReason.I_ELOCALID, errorResponse);
//			}
//			return -1;			
//		}
		
		//
		copyTunningParam(httpRequest.getHttp().getParam());		
		int httpSequence = HttpHelper.invoke(httpRequest);
		if (httpSequence != -1) {
			httpRequest.getHttp().getParam().setListener(httpSequence, httpListener);
			put(new RequestPair(invokeType, httpSequence, httpRequest, httpListener));
		}
		
		return httpSequence;
	}
	
	public synchronized void cancel() {
		for (RequestPair requestPair : mRequestPairMap) {
			cancel(requestPair);
		}
	}
	
	public void cancel(int httpSequence) {
		cancel(get(httpSequence, false));
	}
	
	private synchronized void cancel(RequestPair requestPair) {
		if (requestPair != null && requestPair.getRequest() != null) {
			requestPair.getRequest().getHttp().cancel();
		}
		
		return;
	}
	
	public class RequestPair {
		private int          mInvokeType;
		private int          mSequence;
		private HttpRequest  mRequest;
		private HttpListener mListener;
		
		public RequestPair(int invokeType, int sequence, HttpRequest request, HttpListener listener) {
			mInvokeType = invokeType;
			mSequence   = sequence;
			mRequest    = request;
			mListener   = listener;
		}
		
		public int getInvokeType() {
			return mInvokeType;
		}
		
		public int getSequence() {
			return mSequence;
		}
		
		public HttpRequest getRequest() {
			return mRequest;
		}
		
		public HttpListener getListener() {
			return mListener;
		}
	}
	
	public class TunningParam {
		private int  connTimeo = 0;
		private int  execTimeo = 0;
		private int  maxTries  = 0;
		
		public TunningParam() { ; }
		public TunningParam(int connTimeo, int execTimeo, int maxTries) {
			this.connTimeo = connTimeo;
			this.execTimeo = execTimeo;
			this.maxTries  = maxTries;
		}
		public int getConnectTimeo() {
			return connTimeo;
		}
		public void setConnectTimeo(int connTimeo) {
			this.connTimeo = connTimeo;
		}
		public int getExecTimeo() {
			return execTimeo;
		}
		public void setExecTimeo(int execTimeo) {
			this.execTimeo = execTimeo;
		}
		public int getMaxTries() {
			return maxTries;
		}
		public void setMaxTries(int maxTries) {
			this.maxTries = maxTries;
		}
		
		@Override
		public String toString() {
			return "TunningParam [connTimeo=" + connTimeo + ", execTimeo="
					+ execTimeo + ", maxTries=" + maxTries + "]";
		}
	}
}
