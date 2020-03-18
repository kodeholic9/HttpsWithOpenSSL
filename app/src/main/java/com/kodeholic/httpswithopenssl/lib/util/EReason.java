package com.kodeholic.httpswithopenssl.lib.util;

public class EReason {
	public static final int I_NONE         = -1;
	// remote code
	public static final int I_EOK          =  0;
	public static final int I_EUNDEF       =  1;
	public static final int I_ERESOURCE    =  2;
	public static final int I_ESYSTEM      =  3;
	public static final int I_EPROTO       =  4;
	public static final int I_EROUTE       =  5;
	public static final int I_ETIMEOUT     =  6;
	public static final int I_EDUPLICATED  =  7;
	public static final int I_ETRANSCTION  =  8;
	public static final int I_ESUBS_FROM   =  9;
	public static final int I_EREGISTER    = 10;
	public static final int I_EOVERFLOW    = 11;
	public static final int I_EINPROGRESS  = 12;
	public static final int I_EAGAIN       = 13;
	public static final int I_EPATH        = 15;
	public static final int I_ECOMM        = 16;
	public static final int I_ESUBS_TO     = 17;
	public static final int I_ESESSION     = 18;
	public static final int I_ETOOLONG     = 19;
	public static final int I_ELEFT        = 20;
	public static final int I_EIRREGULAR   = 21; // 전화번호 오류 ( 존재하지 않는 전화번호 )
	public static final int I_ESPAMUSER    = 22;
	public static final int I_EINVALIDATE  = 23;
	public static final int I_EUPDATE      = 24;
	public static final int I_ENOTSUPPORT  = 25;
	public static final int I_EACTION_ERR  = 32; //0x20
	public static final int I_EDUPLICATED2 = 36; //0x24
	public static final int I_EKEYMISMATCH = 37; //0x25

	// http reason
	public static final int I_EPREPARE     = 3001;
	public static final int I_EREQUEST     = 3002;
	public static final int I_ERESPONSE    = 3003;
	public static final int I_EUNREACH     = 3004;
	public static final int I_ECONNTIMEO   = 3005;
	public static final int I_EEXECTIMEO   = 3006;
	public static final int I_EIO          = 3007;
	public static final int I_EPROGRESS    = 3008;
	public static final int I_EEXTEND      = 3009;
	public static final int I_ECANCELED    = 3010;
	public static final int I_EROAMING     = 3011;
	public static final int I_ELOCALID     = 3012;
	// mrs reason
	public static final int I_EUSER        = 4001;
	public static final int I_EIDLE        = 4002;
	// local code
	public static final int I_ELOFFLINE    = 5001;
	public static final int I_ELTIMEO      = 5002;
	public static final int I_ELDAO        = 5003;
	public static final int I_ELUPLOAD     = 5004;
	public static final int I_ELDOWNLOAD   = 5005;
	public static final int I_ELPROC       = 5006;
	public static final int I_ELNOSESSION  = 5007;	
	// reject reason
	public static final int I_EREJECT_USER  = 6001;
	public static final int I_EREJECT_BUSY  = 6002;
	public static final int I_EREJECT_JSI   = 6003;
	public static final int I_EREJECT_CANCEL= 6004;
	
	//app define
	public static final int I_NO_NETWORK   = 100001;
	public static final int I_UNKNOWN_SUBS = 100002;
	public static final int I_NO_SVR_INFO  = 100003;
	public static final int I_POLLER_ERR   = 100004;
	public static final int I_UNKNOWN_ERR  = 100005;
	public static final int I_SEND_ERR     = 100006;
	public static final int I_AIRPLANE_MODE= 100007;
	public static final int I_INCALL       = 100008;
	public static final int I_NO_MOBILE    = 100009;
	public static final int I_ECRYPT       = 100010;
	public static final int I_EUPLOAD      = 100011;
	public static final int I_ECRYPT_CANCEL= 100012;
	public static final int I_ECALL        = 100013;

	/*
	 * HTTP code
	 */
	//Informational response
	public static final int I_HTTP_CONTINUE                  = 100; //Http/1.1 Only
	public static final int I_HTTP_SWITCHING_PROTOCOL        = 101; //Http/1.1 Only
	//successful response
	public static final int I_HTTP_OK                        = 200;  //
	public static final int I_HTTP_CREATED                   = 201;  //
	public static final int I_HTTP_ACCEPTED                  = 202;
	public static final int I_HTTP_NON_AUTH_INFO             = 203;
	public static final int I_HTTP_NO_CONTENT                = 204;
	public static final int I_HTTP_RESET_CONTENT             = 205;
	public static final int I_HTTP_PARTICAL_CONTENT          = 206;
	//redirection message
	public static final int I_HTTP_MULTIPLE_CHOICE           = 300;
	public static final int I_HTTP_MOVED_PERMANENTLY         = 301;
	public static final int I_HTTP_FOUND                     = 302;
	public static final int I_HTTP_SEE_OTHER                 = 303;
	public static final int I_HTTP_NOT_MODIFIED              = 304;
	public static final int I_HTTP_USE_PROXY                 = 305;
	public static final int I_HTTP_UNUSED                    = 306;
	public static final int I_HTTP_TEMPORARY_REDIRECT        = 307;
	public static final int I_HTTP_PERMANENT_REDIRECT        = 308;
	//client error response
	public static final int I_HTTP_BAD_REQUEST               = 400;  //
	public static final int I_HTTP_UNAUTHORIZED              = 401;  //
	public static final int I_HTTP_PAYMENT_REQUIRED          = 402;
	public static final int I_HTTP_FORBIDDEN                 = 403;  //
	public static final int I_HTTP_NOT_FOUND                 = 404;  //
	public static final int I_HTTP_METHOD_NOT_ALLOWED        = 405;
	public static final int I_HTTP_NOT_ACCEPTABLE            = 406;  //
	public static final int I_HTTP_PROXY_AUTH_REQUIRED       = 407;
	public static final int I_HTTP_REQUEST_TIMEOUT           = 408;
	public static final int I_HTTP_CONFLICT                  = 409;
	public static final int I_HTTP_GONE                      = 410;
	public static final int I_HTTP_LENGTH_REQUIRED           = 411;
	public static final int I_HTTP_PERCONDITION_FAILED       = 412;
	public static final int I_HTTP_REQ_ENTITY_TOO_LARGE      = 413;
	public static final int I_HTTP_REQ_URI_TOO_LONG          = 414;
	public static final int I_HTTP_UNSUPPORTED_MEDIA_TYPE    = 415;
	public static final int I_HTTP_REQ_RANGE_NOT_SATISFIABLE = 416;
	public static final int I_HTTP_EXPECTATION_FAILED        = 417;
	public static final int I_HTTP_LOCKED_FAILED        = 423;
	//Server error response
	public static final int I_HTTP_INTERNAL_SERVER_ERROR     = 500;  //
	public static final int I_HTTP_NOT_IMPLEMENTED           = 501;  //
	public static final int I_HTTP_BAD_GATEWAY               = 502;
	public static final int I_HTTP_SERVICE_UNAVAILABLE       = 503;  //
	public static final int I_HTTP_GATEWAY_TIMEOUT           = 504;  //
	public static final int I_HTTP_VERSION_NOT_SUPPORTED     = 505;

	///////////////////////////////////////////////
	public static final String EOK          = "EOK";
	public static final String EUNDEF       = "EUNDEF";
	public static final String ERESOURCE    = "ERESOURCE";
	public static final String ESYSTEM      = "ESYSTEM";
	public static final String EPROTO       = "EPROTO";
	public static final String EROUTE       = "EROUTE";
	public static final String ETIMEOUT     = "ETIMEOUT";
	public static final String EDUPLICATED  = "EDUPLICATED";
	public static final String ETRANSCTION  = "ETRANSCTION";
	public static final String ESUBS_FROM   = "ESUBS_FROM";
	public static final String EREGISTER    = "EREGISTER";
	public static final String EOVERFLOW    = "EOVERFLOW";
	public static final String EINPROGRESS  = "EINPROGRESS";
	public static final String EAGAIN       = "EAGAIN";
	public static final String EPATH        = "EPATH";
	public static final String ECOMM        = "ECOMM";
	public static final String ESUBS_TO     = "ESUBS_TO";
	public static final String ESESSION     = "ESESSION";
	public static final String ETOOLONG     = "ETOOLONG";
	public static final String ELEFT        = "ELEFT";
	public static final String EIRREGULAR   = "EIRREGULAR";
	public static final String ESPAMUSER    = "ESPAMUSER";
	public static final String EINVALIDATE  = "EINVALIDATE";
	public static final String EUPDATE      = "EUPDATE";
	public static final String ENOTSUPPORT  = "ENOTSUPPORT";
	public static final String EACTION_ERR  = "EACTION_ERR";
	
	// http reason
	public static final String EPREPARE     = "EPREPARE";
	public static final String EREQUEST     = "EREQUEST";
	public static final String ERESPONSE    = "ERESPONSE";
	public static final String EUNREACH     = "EUNREACH";
	public static final String ECONNTIMEO   = "ECONNTIMEO";
	public static final String EEXECTIMEO   = "EEXECTIMEO";
	public static final String EIO          = "EIO";
	public static final String EPROGRESS    = "EPROGRESS";
	public static final String EEXTEND      = "EEXTEND";
	public static final String ECANCELED    = "ECANCELED";
	public static final String EROAMING     = "EROAMING";
	public static final String ELOCALID     = "ELOCALID";
	// mrs reason
	public static final String EUSER        = "EUSER";
	public static final String EIDLE        = "EIDLE";
	// local code
	public static final String ELOFFLINE    = "ELOFFLINE";
	public static final String ELTIMEO      = "ELTIMEO";
	public static final String ELDAO        = "ELDAO";
	public static final String ELUPLOAD     = "ELUPLOAD";
	public static final String ELDOWNLOAD   = "ELDOWNLOAD";
	public static final String ELPROC       = "ELPROC";
	public static final String ELNOSESSION  = "ELNOSESSION";	
	// reject reason
	public static final String EREJECT_USER  = "EREJECT_USER";
	public static final String EREJECT_BUSY  = "EREJECT_BUSY";
	public static final String EREJECT_JSI   = "EREJECT_JSI";
	public static final String EREJECT_CANCEL= "EREJECT_CANCEL";
	//app define
	public static final String ENO_NETWORK   = "ENO_NETWORK";
	public static final String EUNKNOWN_SUBS = "EUNKNOWN_SUBS";
	public static final String ENO_SVR_INFO  = "ENO_SVR_INFO";
	public static final String EPOLLER_ERR   = "EPOLLER_ERR";
	public static final String EUNKNOWN_ERR  = "EUNKNOWN_ERR";
	public static final String ESEND_ERR     = "ESEND_ERR";
	public static final String EAIRPLANE_MODE= "EAIRPLANE_MODE";
	public static final String EINCALL       = "EINCALL";
	public static final String ENO_MOBILE    = "ENO_MOBILE";
	public static final String ECALL         = "ECALL";

	/*
	 * HTTP code
	 */
	//Informational response
	public static final String HTTP_CONTINUE                  = "HTTP_CONTINUE"; //Http/1.1 Only
	public static final String HTTP_SWITCHING_PROTOCOL        = "HTTP_SWITCHING_PROTOCOL"; //Http/1.1 Only
	//successful response
	public static final String HTTP_OK                        = "HTTP_OK";  //
	public static final String HTTP_CREATED                   = "HTTP_CREATED";  //
	public static final String HTTP_ACCEPTED                  = "HTTP_ACCEPTED";
	public static final String HTTP_NON_AUTH_INFO             = "HTTP_NON_AUTH_INFO";
	public static final String HTTP_NO_CONTENT                = "HTTP_NO_CONTENT";
	public static final String HTTP_RESET_CONTENT             = "HTTP_RESET_CONTENT";
	public static final String HTTP_PARTICAL_CONTENT          = "HTTP_PARTICAL_CONTENT";
	//redirection message
	public static final String HTTP_MULTIPLE_CHOICE           = "HTTP_MULTIPLE_CHOICE";
	public static final String HTTP_MOVED_PERMANENTLY         = "HTTP_MOVED_PERMANENTLY";
	public static final String HTTP_FOUND                     = "HTTP_FOUND";
	public static final String HTTP_SEE_OTHER                 = "HTTP_SEE_OTHER";
	public static final String HTTP_NOT_MODIFIED              = "HTTP_NOT_MODIFIED";
	public static final String HTTP_USE_PROXY                 = "HTTP_USE_PROXY";
	public static final String HTTP_UNUSED                    = "HTTP_UNUSED";
	public static final String HTTP_TEMPORARY_REDIRECT        = "HTTP_TEMPORARY_REDIRECT";
	public static final String HTTP_PERMANENT_REDIRECT        = "HTTP_PERMANENT_REDIRECT";
	//client error response
	public static final String HTTP_BAD_REQUEST               = "HTTP_BAD_REQUEST";  //
	public static final String HTTP_UNAUTHORIZED              = "HTTP_UNAUTHORIZED";  //
	public static final String HTTP_PAYMENT_REQUIRED          = "HTTP_PAYMENT_REQUIRED";
	public static final String HTTP_FORBIDDEN                 = "HTTP_FORBIDDEN";  //
	public static final String HTTP_NOT_FOUND                 = "HTTP_NOT_FOUND";  //
	public static final String HTTP_METHOD_NOT_ALLOWED        = "HTTP_METHOD_NOT_ALLOWED";
	public static final String HTTP_NOT_ACCEPTABLE            = "HTTP_NOT_ACCEPTABLE";  //
	public static final String HTTP_PROXY_AUTH_REQUIRED       = "HTTP_PROXY_AUTH_REQUIRED";
	public static final String HTTP_REQUEST_TIMEOUT           = "HTTP_REQUEST_TIMEOUT";
	public static final String HTTP_CONFLICT                  = "HTTP_CONFLICT";
	public static final String HTTP_GONE                      = "HTTP_GONE";
	public static final String HTTP_LENGTH_REQUIRED           = "HTTP_LENGTH_REQUIRED";
	public static final String HTTP_PERCONDITION_FAILED       = "HTTP_PERCONDITION_FAILED";
	public static final String HTTP_REQ_ENTITY_TOO_LARGE      = "HTTP_REQ_ENTITY_TOO_LARGE";
	public static final String HTTP_REQ_URI_TOO_LONG          = "HTTP_REQ_URI_TOO_LONG";
	public static final String HTTP_UNSUPPORTED_MEDIA_TYPE    = "HTTP_UNSUPPORTED_MEDIA_TYPE";
	public static final String HTTP_REQ_RANGE_NOT_SATISFIABLE = "HTTP_REQ_RANGE_NOT_SATISFIABLE";
	public static final String HTTP_EXPECTATION_FAILED        = "HTTP_EXPECTATION_FAILED";
	public static final String HTTP_LOCKED_FAILED        = "HTTP_LOCKED_FAILED";
	//Server error response
	public static final String HTTP_INTERNAL_SERVER_ERROR     = "HTTP_INTERNAL_SERVER_ERROR";  //
	public static final String HTTP_NOT_IMPLEMENTED           = "HTTP_NOT_IMPLEMENTED";  //
	public static final String HTTP_BAD_GATEWAY               = "HTTP_BAD_GATEWAY";
	public static final String HTTP_SERVICE_UNAVAILABLE       = "HTTP_SERVICE_UNAVAILABLE";  //
	public static final String HTTP_GATEWAY_TIMEOUT           = "HTTP_GATEWAY_TIMEOUT";  //
	public static final String HTTP_VERSION_NOT_SUPPORTED     = "HTTP_VERSION_NOT_SUPPORTED";
	
	public static String valueOf(int code) {
		switch (code) {
		case I_EOK          : return EOK;
		case I_EUNDEF       : return EUNDEF;
		case I_ERESOURCE    : return ERESOURCE;
		case I_ESYSTEM      : return ESYSTEM;
		case I_EPROTO       : return EPROTO;
		case I_EROUTE       : return EROUTE;
		case I_ETIMEOUT     : return ETIMEOUT;
		case I_EDUPLICATED  : return EDUPLICATED;
		case I_ETRANSCTION  : return ETRANSCTION;
		case I_ESUBS_FROM   : return ESUBS_FROM;
		case I_EREGISTER    : return EREGISTER;
		case I_EOVERFLOW    : return EOVERFLOW;
		case I_EINPROGRESS  : return EINPROGRESS;
		case I_EAGAIN       : return EAGAIN;
		case I_EPATH        : return EPATH;
		case I_ECOMM        : return ECOMM;
		case I_ESUBS_TO     : return ESUBS_TO;
		case I_ESESSION     : return ESESSION;
		case I_ETOOLONG     : return ETOOLONG;
		case I_ELEFT        : return ELEFT;
		case I_EIRREGULAR   : return EIRREGULAR;
		case I_ESPAMUSER    : return ESPAMUSER;
		case I_EINVALIDATE  : return EINVALIDATE;
		case I_EUPDATE      : return EUPDATE;	
		case I_ENOTSUPPORT  : return ENOTSUPPORT;
		case I_EACTION_ERR  : return EACTION_ERR;
		case I_EDUPLICATED2 : return EDUPLICATED;
		
		// http reason
		case I_EPREPARE     : return EPREPARE;
		case I_EREQUEST     : return EREQUEST;
		case I_ERESPONSE    : return ERESPONSE;
		case I_EUNREACH     : return EUNREACH;
		case I_ECONNTIMEO   : return ECONNTIMEO;
		case I_EEXECTIMEO   : return EEXECTIMEO;
		case I_EIO          : return EIO;
		case I_EPROGRESS    : return EPROGRESS;
		case I_ECANCELED    : return ECANCELED;
		case I_EROAMING     : return EROAMING;
		case I_ELOCALID     : return ELOCALID;
		// local code
		case I_ELOFFLINE    : return ELOFFLINE;
		case I_ELTIMEO      : return ELTIMEO;
		case I_ELDAO        : return ELDAO;
		case I_ELUPLOAD     : return ELUPLOAD;
		case I_ELDOWNLOAD   : return ELDOWNLOAD;
		case I_ELPROC       : return ELPROC;
		case I_ELNOSESSION  : return ELNOSESSION;
		// mrs reason
		case I_EUSER        : return EUSER;
		case I_EIDLE        : return EIDLE;	
		// reject reason
		case I_EREJECT_USER  : return EREJECT_USER;
		case I_EREJECT_BUSY  : return EREJECT_BUSY;
		case I_EREJECT_JSI   : return EREJECT_JSI;
		case I_EREJECT_CANCEL: return EREJECT_CANCEL;
		
		//app define
		case I_NO_NETWORK   : return ENO_NETWORK;
		case I_UNKNOWN_SUBS : return EUNKNOWN_SUBS;
		case I_NO_SVR_INFO  : return ENO_SVR_INFO;
		case I_POLLER_ERR   : return EPOLLER_ERR;
		case I_UNKNOWN_ERR  : return EUNKNOWN_ERR;
		case I_SEND_ERR     : return ESEND_ERR;		
		case I_AIRPLANE_MODE: return EAIRPLANE_MODE;		
		case I_INCALL       : return EINCALL;		
		case I_NO_MOBILE    : return ENO_MOBILE;
		case I_ECALL        : return ECALL;

			//http
        //Informational response
        case I_HTTP_CONTINUE           : return HTTP_CONTINUE;
        case I_HTTP_SWITCHING_PROTOCOL : return HTTP_SWITCHING_PROTOCOL;
        //successful response    
        case I_HTTP_OK                 : return HTTP_OK;
        case I_HTTP_CREATED            : return HTTP_CREATED;
        case I_HTTP_ACCEPTED           : return HTTP_ACCEPTED;
        case I_HTTP_NON_AUTH_INFO      : return HTTP_NON_AUTH_INFO;
        case I_HTTP_NO_CONTENT         : return HTTP_NO_CONTENT;
        case I_HTTP_RESET_CONTENT      : return HTTP_RESET_CONTENT;
        case I_HTTP_PARTICAL_CONTENT   : return HTTP_PARTICAL_CONTENT;
        //redirection message	
        case I_HTTP_MULTIPLE_CHOICE    : return HTTP_MULTIPLE_CHOICE;
        case I_HTTP_MOVED_PERMANENTLY  : return HTTP_MOVED_PERMANENTLY;
        case I_HTTP_FOUND              : return HTTP_FOUND;
        case I_HTTP_SEE_OTHER          : return HTTP_SEE_OTHER;
        case I_HTTP_NOT_MODIFIED       : return HTTP_NOT_MODIFIED;
        case I_HTTP_USE_PROXY          : return HTTP_USE_PROXY;
        case I_HTTP_UNUSED             : return HTTP_UNUSED;
        case I_HTTP_TEMPORARY_REDIRECT : return HTTP_TEMPORARY_REDIRECT;
        case I_HTTP_PERMANENT_REDIRECT : return HTTP_PERMANENT_REDIRECT;
        //client error response	
        case I_HTTP_BAD_REQUEST              : return HTTP_BAD_REQUEST;
        case I_HTTP_UNAUTHORIZED             : return HTTP_UNAUTHORIZED;
        case I_HTTP_PAYMENT_REQUIRED         : return HTTP_PAYMENT_REQUIRED;
        case I_HTTP_FORBIDDEN                : return HTTP_FORBIDDEN;
        case I_HTTP_NOT_FOUND                : return HTTP_NOT_FOUND;
        case I_HTTP_METHOD_NOT_ALLOWED       : return HTTP_METHOD_NOT_ALLOWED;
        case I_HTTP_NOT_ACCEPTABLE           : return HTTP_NOT_ACCEPTABLE;
        case I_HTTP_PROXY_AUTH_REQUIRED      : return HTTP_PROXY_AUTH_REQUIRED;
        case I_HTTP_REQUEST_TIMEOUT          : return HTTP_REQUEST_TIMEOUT;
        case I_HTTP_CONFLICT                 : return HTTP_CONFLICT;            	
        case I_HTTP_GONE                     : return HTTP_GONE;            	
        case I_HTTP_LENGTH_REQUIRED          : return HTTP_LENGTH_REQUIRED;            	
        case I_HTTP_PERCONDITION_FAILED      : return HTTP_PERCONDITION_FAILED;            	
        case I_HTTP_REQ_ENTITY_TOO_LARGE     : return HTTP_REQ_ENTITY_TOO_LARGE;            	
        case I_HTTP_REQ_URI_TOO_LONG         : return HTTP_REQ_URI_TOO_LONG;            	
        case I_HTTP_UNSUPPORTED_MEDIA_TYPE   : return HTTP_UNSUPPORTED_MEDIA_TYPE;            	
        case I_HTTP_REQ_RANGE_NOT_SATISFIABLE: return HTTP_REQ_RANGE_NOT_SATISFIABLE;            	
        case I_HTTP_EXPECTATION_FAILED       : return HTTP_EXPECTATION_FAILED;
        case I_HTTP_LOCKED_FAILED       	: return HTTP_LOCKED_FAILED;
        //Server error response	
        case I_HTTP_INTERNAL_SERVER_ERROR: return HTTP_INTERNAL_SERVER_ERROR;            	
        case I_HTTP_NOT_IMPLEMENTED      : return HTTP_NOT_IMPLEMENTED;            	
        case I_HTTP_BAD_GATEWAY          : return HTTP_BAD_GATEWAY;            	
        case I_HTTP_SERVICE_UNAVAILABLE  : return HTTP_SERVICE_UNAVAILABLE;            	
        case I_HTTP_GATEWAY_TIMEOUT      : return HTTP_GATEWAY_TIMEOUT;            	
        case I_HTTP_VERSION_NOT_SUPPORTED: return HTTP_VERSION_NOT_SUPPORTED; 
		}
		
		return "UNK(" + code + ")";
	}
	
	public static int valueOf(String s, boolean check) throws Exception {
		if      (s.compareTo(EOK          ) == 0) return I_EOK;
		else if (s.compareTo(EUNDEF       ) == 0) return I_EUNDEF;
		else if (s.compareTo(ERESOURCE    ) == 0) return I_ERESOURCE;
		else if (s.compareTo(ESYSTEM      ) == 0) return I_ESYSTEM;
		else if (s.compareTo(EPROTO       ) == 0) return I_EPROTO;
		else if (s.compareTo(EROUTE       ) == 0) return I_EROUTE;
		else if (s.compareTo(ETIMEOUT     ) == 0) return I_ETIMEOUT;
		else if (s.compareTo(EDUPLICATED  ) == 0) return I_EDUPLICATED;
		else if (s.compareTo(ETRANSCTION  ) == 0) return I_ETRANSCTION;
		else if (s.compareTo(ESUBS_FROM   ) == 0) return I_ESUBS_FROM;
		else if (s.compareTo(EREGISTER    ) == 0) return I_EREGISTER;
		else if (s.compareTo(EOVERFLOW    ) == 0) return I_EOVERFLOW;
		else if (s.compareTo(EINPROGRESS  ) == 0) return I_EINPROGRESS;
		else if (s.compareTo(EAGAIN       ) == 0) return I_EAGAIN;
		else if (s.compareTo(EPATH        ) == 0) return I_EPATH;
		else if (s.compareTo(ECOMM        ) == 0) return I_ECOMM;
		else if (s.compareTo(ESUBS_TO     ) == 0) return I_ESUBS_TO;
		else if (s.compareTo(ESESSION     ) == 0) return I_ESESSION;
		else if (s.compareTo(ETOOLONG     ) == 0) return I_ETOOLONG;
		else if (s.compareTo(ELEFT        ) == 0) return I_ELEFT;
		else if (s.compareTo(EIRREGULAR   ) == 0) return I_EIRREGULAR;
		else if (s.compareTo(ESPAMUSER    ) == 0) return I_ESPAMUSER;
		else if (s.compareTo(EINVALIDATE  ) == 0) return I_EINVALIDATE;
		else if (s.compareTo(EUPDATE      ) == 0) return I_EUPDATE;	
		else if (s.compareTo(ENOTSUPPORT  ) == 0) return I_ENOTSUPPORT;
		else if (s.compareTo(EACTION_ERR  ) == 0) return I_EACTION_ERR;	
		// http reason
		else if (s.compareTo(EPREPARE     ) == 0) return I_EPREPARE;
		else if (s.compareTo(EREQUEST     ) == 0) return I_EREQUEST;
		else if (s.compareTo(ERESPONSE    ) == 0) return I_ERESPONSE;
		else if (s.compareTo(EUNREACH     ) == 0) return I_EUNREACH;
		else if (s.compareTo(ECONNTIMEO   ) == 0) return I_ECONNTIMEO;
		else if (s.compareTo(EEXECTIMEO   ) == 0) return I_EEXECTIMEO;
		else if (s.compareTo(EIO          ) == 0) return I_EIO;
		else if (s.compareTo(EPROGRESS    ) == 0) return I_EPROGRESS;
		else if (s.compareTo(ECANCELED    ) == 0) return I_ECANCELED;
		else if (s.compareTo(EROAMING     ) == 0) return I_EROAMING;
		else if (s.compareTo(ELOCALID     ) == 0) return I_ELOCALID;
		// local code
		else if (s.compareTo(ELOFFLINE    ) == 0) return I_ELOFFLINE;
		else if (s.compareTo(ELTIMEO      ) == 0) return I_ELTIMEO;
		else if (s.compareTo(ELDAO        ) == 0) return I_ELDAO;
		else if (s.compareTo(ELUPLOAD     ) == 0) return I_ELUPLOAD;
		else if (s.compareTo(ELDOWNLOAD   ) == 0) return I_ELDOWNLOAD;
		else if (s.compareTo(ELPROC       ) == 0) return I_ELPROC;
		else if (s.compareTo(ELNOSESSION  ) == 0) return I_ELNOSESSION;
		// mrs reason
		else if (s.compareTo(EUSER        ) == 0) return I_EUSER;
		else if (s.compareTo(EIDLE        ) == 0) return I_EIDLE;	
		// reject reason
		else if (s.compareTo(EREJECT_USER  ) == 0) return I_EREJECT_USER;
		else if (s.compareTo(EREJECT_BUSY  ) == 0) return I_EREJECT_BUSY;
		else if (s.compareTo(EREJECT_JSI   ) == 0) return I_EREJECT_JSI;
		else if (s.compareTo(EREJECT_CANCEL) == 0) return I_EREJECT_CANCEL;
		else if (check) {
			throw new Exception("UNKNOWN EReason[" + s + "]");
		}
		
		return I_NONE;
	}
	
	public static int valueOf(String s) {
		try {
			return valueOf(s, false);
		}
		catch (Exception ignore) { ; }
		
		return I_NONE;
	}

	public static boolean isEPermanent(int error) {
		switch (error) {
			//case I_EOK          :
			case I_EUNDEF       :
			case I_ERESOURCE    :
			case I_ESYSTEM      :
			case I_EPROTO       :
			//case I_EROUTE       :
			//case I_ETIMEOUT     :
			//case I_EDUPLICATED  :
			//case I_ETRANSCTION  :
			case I_ESUBS_FROM   :
			case I_EREGISTER    :
			//case I_EOVERFLOW    :
			//case I_EINPROGRESS  :
			case I_EAGAIN       :
			case I_EPATH        :
			case I_ECOMM        :
			case I_ESUBS_TO     :
			case I_ESESSION     :
			case I_ETOOLONG     :
			case I_ELEFT        :
			case I_EIRREGULAR   :
			case I_ESPAMUSER    :
			case I_EINVALIDATE  :
			//case I_EUPDATE      :
			case I_ENOTSUPPORT  :
			case I_EACTION_ERR  :
			//case I_EDUPLICATED2 :
			case I_EKEYMISMATCH :
				return true;
		}

		return false;
	}
}
