package com.kodeholic.httpswithopenssl.lib.http;

import com.kodeholic.httpswithopenssl.lib.util.EReason;

import java.io.File;
import java.net.HttpURLConnection;

public class HttpResponse {
	private int    invokeType;
	private int    reason; // EReason.xxx
	private int    httpCode;
	//
	private int    step;
	private String contents;
	private File   file;
	//
	private Object object;

	//
	private long responseTime = -1;
	
	public HttpResponse() { ; }
	public HttpResponse(int reason) {
		this.reason     = reason;
	}
	public HttpResponse(int reason, int httpCode, String contents) {
		this.reason     = reason;
		this.httpCode   = httpCode;
		this.contents   = contents;
	}

	public HttpResponse(int reason, int httpCode, String contents, long responseTime) {
		this.reason      = reason;
		this.httpCode    = httpCode;
		this.contents    = contents;
		this.responseTime= responseTime;
	}

	public boolean isSUCC() { return  isEOK() && isHTTP_200(); }
	public boolean isFAIL() { return !isSUCC(); }
	
	//OK,CANCEL
	public boolean isEOK      () { return (this.reason == EReason.I_EOK); }
	public boolean isECANCELED() { return (this.reason == EReason.I_ECANCELED); }
	public boolean isEAirplain() { return (this.reason == EReason.I_AIRPLANE_MODE); }
	public boolean isETIMEOUT()  { return (this.reason == EReason.I_ETIMEOUT || this.reason == EReason.I_ECONNTIMEO); }

	//200~
	public boolean isHTTP_200() { return (this.httpCode == HttpURLConnection.HTTP_OK); }
	public boolean isHTTP_201() { return (this.httpCode == HttpURLConnection.HTTP_CREATED); }
	//300~
	//400~
	public boolean isHTTP_400() { return (this.httpCode == HttpURLConnection.HTTP_BAD_REQUEST); }
	public boolean isHTTP_401() { return (this.httpCode == HttpURLConnection.HTTP_UNAUTHORIZED); }
	public boolean isHTTP_403() { return (this.httpCode == HttpURLConnection.HTTP_FORBIDDEN); }
	public boolean isHTTP_404() { return (this.httpCode == HttpURLConnection.HTTP_NOT_FOUND); }
	public boolean isHTTP_406() { return (this.httpCode == HttpURLConnection.HTTP_NOT_ACCEPTABLE); }
	//500~
	public boolean isHTTP_500() { return (this.httpCode == HttpURLConnection.HTTP_INTERNAL_ERROR); }
	public boolean isHTTP_501() { return (this.httpCode == HttpURLConnection.HTTP_NOT_IMPLEMENTED); }
	public boolean isHTTP_503() { return (this.httpCode == HttpURLConnection.HTTP_UNAVAILABLE); }
	public boolean isHTTP_504() { return (this.httpCode == HttpURLConnection.HTTP_GATEWAY_TIMEOUT); }
	
	public boolean hasContents() {
		return (contents != null && contents.length() > 0);
	}
	
	public String getContents() {
		if (contents          == null) return null;
		if (contents.length() == 0   ) return null;
		
		// replace...
		if (contents.length() <= 7) {
			String trimed = contents.replace(" ", "").trim();
			if (trimed.equalsIgnoreCase("{}")) return null;			
		}
		
		return contents;
	}
	
	public void setContents(String contents) {
		this.contents = contents;
	}
	
	public File getFile() {
		return file;
	}
	public void setFile(File file) {
		this.file = file;
	}
	
	public int getHttpCode() {
		return httpCode;
	}
	public void setHttpCode(int httpCode) {
		this.httpCode = httpCode;
	}
	
	public int getStep() {
		return step;
	}	
	public void setStep(int step) {
		this.step = step;
	}
	
	public int getInvokeType() {
		return invokeType;
	}
	public void setInvokeType(int invokeType) {
		this.invokeType = invokeType;
	}
	
	public int getHttpReason() {
		return reason;
	}
	public void setHttpReason(int httpReason) {
		this.reason = httpReason;
	}
	
	public void setObject(Object object) {
		this.object = object;
	}
	
	public Object getObject() {
		return this.object;
	}

	public long getResponseTime() {
		return responseTime;
	}

	public void setResponseTime(long responseTime) {
		this.responseTime = responseTime;
	}

	@Override
	public String toString() {
		return "HttpResponse{" +
				"invokeType=" + invokeType +
				", reason=" + reason +
				", httpCode=" + httpCode +
				", step=" + step +
				", contents='" + contents + '\'' +
				", file=" + file +
				", object=" + object +
				", responseTime=" + responseTime +
				'}';
	}

	public String toDisplay() {
		return "type: " + invokeType + ", reason: " + EReason.valueOf(reason) + ", httpCode: " + httpCode;
	}
}
