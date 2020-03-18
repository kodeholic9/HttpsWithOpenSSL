package com.kodeholic.httpswithopenssl.lib.http;

import android.content.Context;


public abstract class HttpRequest implements HttpListener {
	protected HttpUtil mHttp = null;
	protected int      mHttpSequence = 0;
	
	public HttpRequest(Context context) {
		this.mHttp         = new HttpUtil(context);
		this.mHttpSequence = 0;
	}
	
	public HttpUtil getHttp(){ return this.mHttp; }
	public int      getHttpSequence() { return this.mHttpSequence; }
	public void setHttpSequence(int httpSequence) {
		this.mHttpSequence = httpSequence;
		this.mHttp.setHttpSequence(httpSequence);
	}
	
	// abstract
	abstract public int  onRequest () throws Exception;
	
	@Override
	public void onProgress(int httpSequence, int current, int total) { ; }
}
