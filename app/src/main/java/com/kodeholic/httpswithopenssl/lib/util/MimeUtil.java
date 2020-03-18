package com.kodeholic.httpswithopenssl.lib.util;

import java.util.ArrayList;
import java.util.List;

public class MimeUtil {
	private final static List<MimeMap> mimeMaps = new ArrayList<MimeMap>();
	static {
		/* for text */
		mimeMaps.add(new MimeMap("txt", "text/plain"));
		
		/* for html */
		mimeMaps.add(new MimeMap("htm"  , "text/html"));
		mimeMaps.add(new MimeMap("html" , "text/html"));
		mimeMaps.add(new MimeMap("htmls", "text/html"));
		
		/* for image */
		mimeMaps.add(new MimeMap("jpeg", "image/jpeg"));
		mimeMaps.add(new MimeMap("jpg" , "image/jpeg"));
		mimeMaps.add(new MimeMap("jpe" , "image/jpeg"));
		mimeMaps.add(new MimeMap("gif" , "image/gif"));
		mimeMaps.add(new MimeMap("png" , "image/png"));
		mimeMaps.add(new MimeMap("bmp" , "image/bmp"));
		
		/* for audio */
		mimeMaps.add(new MimeMap("mp3" , "audio/mp3"));
		mimeMaps.add(new MimeMap("wav" , "audio/wav"));
		mimeMaps.add(new MimeMap("m4a" , "audio/mpeg")); //리얼톡
		mimeMaps.add(new MimeMap("wma" , "audio/x-ms-wma")); //리얼톡
		
		/* for video */
		mimeMaps.add(new MimeMap("mp4"   , "video/mp4"));		
		mimeMaps.add(new MimeMap("3gp"   , "video/3gp"));		
		mimeMaps.add(new MimeMap("3gpp"  , "video/3gpp"));		
		mimeMaps.add(new MimeMap("3gppp2", "video/3gppp2"));
		mimeMaps.add(new MimeMap("mpeg", "video/mpeg"));
		mimeMaps.add(new MimeMap("mpg" , "video/mpeg"));
		mimeMaps.add(new MimeMap("mpe" , "video/mpeg"));
		mimeMaps.add(new MimeMap("qt"  , "video/quicktime"));
		mimeMaps.add(new MimeMap("mov" , "video/quicktime"));
		mimeMaps.add(new MimeMap("avi" , "video/x-msvideo"));
		mimeMaps.add(new MimeMap("wmv" , "video/x-ms-wmv")); //리얼톡
		mimeMaps.add(new MimeMap("asf" , "video/x-ms-asf")); //리얼톡

		/* for doc */
		mimeMaps.add(new MimeMap("pdf" , "application/pdf"));
		
		mimeMaps.add(new MimeMap("xla", "application/vnd.ms-excel"));
		mimeMaps.add(new MimeMap("xlc", "application/vnd.ms-excel")); 
		mimeMaps.add(new MimeMap("xlm", "application/vnd.ms-excel")); 
		mimeMaps.add(new MimeMap("xls", "application/vnd.ms-excel")); 
		mimeMaps.add(new MimeMap("xlt", "application/vnd.ms-excel")); 		
		mimeMaps.add(new MimeMap("xlw", "application/vnd.ms-excel")); 
		
		mimeMaps.add(new MimeMap("pot", "application/vnd.ms-powerpoint"));
		mimeMaps.add(new MimeMap("pps", "application/vnd.ms-powerpoint"));
		mimeMaps.add(new MimeMap("ppt", "application/vnd.ms-powerpoint"));
		
		mimeMaps.add(new MimeMap("doc", "application/msword"));
		mimeMaps.add(new MimeMap("dot", "application/msword"));
		
		mimeMaps.add(new MimeMap("xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"));
		mimeMaps.add(new MimeMap("xltx", "application/vnd.openxmlformats-officedocument.spreadsheetml.template"));
		mimeMaps.add(new MimeMap("potx", "application/vnd.openxmlformats-officedocument.presentationml.template"));
		mimeMaps.add(new MimeMap("ppsx", "application/vnd.openxmlformats-officedocument.presentationml.slideshow"));
		mimeMaps.add(new MimeMap("pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation"));
		mimeMaps.add(new MimeMap("sldx", "application/vnd.openxmlformats-officedocument.presentationml.slide"));
		mimeMaps.add(new MimeMap("docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"));
		mimeMaps.add(new MimeMap("dotx", "application/vnd.openxmlformats-officedocument.wordprocessingml.template"));
		mimeMaps.add(new MimeMap("xlam", "application/vnd.ms-excel.addin.macroEnabled.12"));
		mimeMaps.add(new MimeMap("xlsb", "application/vnd.ms-excel.sheet.binary.macroEnabled.12"));

		mimeMaps.add(new MimeMap("msg", "application/vnd.ms-outlook"));   
		mimeMaps.add(new MimeMap("sst", "application/vnd.ms-pkicertstore"));
		mimeMaps.add(new MimeMap("cat", "application/vnd.ms-pkiseccat"));
		mimeMaps.add(new MimeMap("stl", "application/vnd.ms-pkistl"));
		mimeMaps.add(new MimeMap("mpp", "application/vnd.ms-project"));
		mimeMaps.add(new MimeMap("wcm", "application/vnd.ms-works"));
		mimeMaps.add(new MimeMap("wdb", "application/vnd.ms-works"));
		mimeMaps.add(new MimeMap("wks", "application/vnd.ms-works"));
		mimeMaps.add(new MimeMap("wps", "application/vnd.ms-works"));
		
		mimeMaps.add(new MimeMap("hwp", "application/x-hwp")); //리얼톡

		}

	public static String getMimeTypeFromFile(String fileName) throws Exception {
		int pos = fileName.lastIndexOf(".");
		if (pos == -1) {
			throw new Exception("NO DOT - " + fileName);
		}
		String extention = fileName.substring(pos + 1);
		for (MimeMap map : mimeMaps) {
			if (map.getExtention().compareToIgnoreCase(extention) == 0) {
				return map.getMimeType();
			}
		}
		
		//throw new Exception("NO SUCH MIME MAP - " + fileName + "(" + extention + ")");
		return "application/octet-stream";
	}
	
	public static class MimeMap {
		private String extention;
		private String mimeType;
		public MimeMap(String extention, String mimeType) {
			this.extention = extention;
			this.mimeType  = mimeType;
		}
		public String getExtention() {
			return extention;
		}
		public void setExtention(String extention) {
			this.extention = extention;
		}
		public String getMimeType() {
			return mimeType;
		}
		public void setMimeType(String mimeType) {
			this.mimeType = mimeType;
		}		
	}
}
