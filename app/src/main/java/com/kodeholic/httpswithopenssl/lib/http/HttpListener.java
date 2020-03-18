package com.kodeholic.httpswithopenssl.lib.http;


public interface HttpListener {
	public void onProgress(int httpSequence, int current, int total);
	public void onResponse(int httpSequence, int httpReason, HttpResponse httpResponse);
}


