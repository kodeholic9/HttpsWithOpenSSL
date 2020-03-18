package com.kodeholic.httpswithopenssl.lib.http;


import com.kodeholic.httpswithopenssl.lib.util.EReason;
import com.kodeholic.httpswithopenssl.lib.util.Log;

public class HttpHelper {
	public static final String LOG_TAG = HttpHelper.class.getSimpleName();
	
	private HttpController controller;
	private static final HttpHelper instance = new HttpHelper();
	private HttpHelper() {
		//System.setProperty("http.keepAlive", "false");
		controller = new HttpController(16);
	}	
	public static HttpHelper getInstance() {
		return instance;
	}
	public static int invoke(HttpRequest httpRequest) {
		return instance.controller.invoke(httpRequest);
	}	
	public HttpController getHttpController() {
		return controller;
	}
	
	public class HttpController {	
		public int maxRunners;
		public int currentRunners  = 0;
		public int sequence        = 0;
		
		public HttpController(int maxRunners) {
			this.maxRunners = maxRunners;
		}
		public synchronized int invoke(HttpRequest httpRequest) {
			if (this.currentRunners >= maxRunners) {
				return -1;
			}
			this.currentRunners += 1;
			this.sequence       += 1;
			
			Log.w(LOG_TAG, "RUNNER(" + this.sequence + ") INVOKED (" + this.currentRunners + ")");
			Thread runner = new Thread(new HttpTask(httpRequest, this.sequence));
			runner.start();
			
			return this.sequence;
		}
		
		public synchronized void release(int httpSequence) {
			this.currentRunners -= 1;
			Log.w(LOG_TAG, "RUNNER(" + httpSequence + ") RELEASED (" + this.currentRunners + ")");
		}	
		
		public class HttpTask implements Runnable {
			private HttpRequest  httpRequest;
			
			public HttpTask(HttpRequest  httpRequest, int httpSequence) {
				this.httpRequest = httpRequest;
				this.httpRequest.setHttpSequence(httpSequence);
			}

			private int request() {
				// onExecute
				try {
					return httpRequest.onRequest();
				}
				catch (Exception e) { e.printStackTrace();
				}
				finally {
					HttpController.this.release(httpRequest.getHttpSequence());
				}
				
				return EReason.I_EREQUEST;
			}
			
	        private void afterRequest(int httpReason) {
				// onResponse
				try {
					if (httpReason == EReason.I_EOK) {
						int    status   = httpRequest.getHttp().getResponseCode();
						String contents = httpRequest.getHttp().getResponseContent();
						httpRequest.onResponse(httpRequest.getHttpSequence(), httpReason, new HttpResponse(httpReason, status, contents));
					}
					else {
						httpRequest.onResponse(httpRequest.getHttpSequence(), httpReason, new HttpResponse(httpReason));
					}
				}
				catch (Exception e) { e.printStackTrace(); 
				}			
				
				return;
	        }

			@Override
			public void run() { afterRequest(request()); }
		}
	}
}
