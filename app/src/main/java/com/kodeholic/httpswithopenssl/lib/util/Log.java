package com.kodeholic.httpswithopenssl.lib.util;

public class Log {
	public static boolean SHOW_DEBUG = true;

	public static void debug(boolean debug) {
		SHOW_DEBUG = debug;
	}

	public static void d(String tag, String contents) {
		if (SHOW_DEBUG) {
			android.util.Log.d(tag, contents);
		}
	}

	public static void i(String tag, String contents) {
		if (SHOW_DEBUG) {
			android.util.Log.i(tag, contents);
		}
	}

	public static void e(String tag, String contents) {
		if (SHOW_DEBUG) {
			android.util.Log.e(tag, contents);
		}
	}

	public static void e(String tag, String contents, Throwable e) {
		if (SHOW_DEBUG) {
			e.printStackTrace();
			android.util.Log.e(tag, contents);
		}
	}

	public static void v(String tag, String contents) {
		if (SHOW_DEBUG) { 
			android.util.Log.v(tag, contents);
		}
	}

	public static void w(String tag, String contents) {
		if (SHOW_DEBUG) {
			android.util.Log.w(tag, contents);
		}
	}

	public static void w(String tag, String contents, Throwable e) {
		if (SHOW_DEBUG) {
			e.printStackTrace();
			android.util.Log.w(tag, contents);
		}
	}
}
