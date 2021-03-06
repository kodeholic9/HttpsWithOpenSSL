package com.kodeholic.httpswithopenssl.lib.util;

import com.google.gson.Gson;
import com.kodeholic.httpswithopenssl.lib.http.HttpResponse;

import java.util.Arrays;
import java.util.List;

public class JSUtil {
	private static Gson[] sGson = {
			new Gson(), new Gson(), new Gson(), new Gson(), new Gson(),
			new Gson(), new Gson(), new Gson(), new Gson(), new Gson(),
	};

	private static int sIndex = 0;

	private static synchronized int INDEX() {
		if ((sIndex += 1) >= 10000) {
			sIndex = 0;
		}
		return sIndex % sGson.length;
	}
	/**
	 * JSON 문자열을 Object로 변환한다.
	 * @param str
	 * @param classOfT
	 * @return
	 */
	public static <T>T json2Object(String str, Class<T> classOfT) {
		int index = INDEX();
		synchronized (sGson[index]) {
			return sGson[index].fromJson(str, classOfT);
		}
	}
	
	/**
	 * JSON 문자열을 Object로 변환한다.
	 * @param response
	 * @param classOfT
	 * @return
	 */
	public static <T>T json2Object(HttpResponse response, Class<T> classOfT) {
		return json2Object(response.getContents(), classOfT);
	}

	/**
	 * JSON 문자열 리스트를 Object로 변환한다.
	 * @param str
	 * @param classOfT
	 * @return
	 */
	public static <T> List<T> jsonList2Object(String str, Class<T[]> classOfT) {
		T[] json2Object = new Gson().fromJson(str, classOfT);
		return Arrays.asList(json2Object);
	}
	
	/**
	 * JSON Object를 문자열로 변환한다.
	 * @param obj
	 * @return
	 */
	public static String json2String(Object obj) {
		int index = INDEX();
		synchronized (sGson[index]) {
			return sGson[index].toJson(obj);
		}
	}
}
