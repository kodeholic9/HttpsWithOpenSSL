#include <jni.h>
#include <string.h>
#include <android/log.h>
#include <stdlib.h>
#include <stdio.h>
#include <linux/in.h>
#include <netdb.h>
#include <endian.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <zconf.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/crypto.h>


#ifdef __cplusplus
extern "C" {
#endif

#include "ti2.h"

static const char *TAG = "TI2TLS";
static const int MAX_BUFFER_SIZE (32*1024);

///////////////////////////////////////////////////////
//
// native C code..
//
///////////////////////////////////////////////////////

///////////////////////////////////////////////////////
// struct
///////////////////////////////////////////////////////
#define MAX_TLS_CONN_NUM 64
#define MAX_TLS_LOCK_NUM 10

#define TLSCONN_CHK(iidd)  (iidd >= 0 && iidd < MAX_TLS_CONN_NUM)
#define TLSCONN_PTR(iidd)  (pOz->tlsconn + iidd)
#define TLSCONN_ID(ppttrr) ((int)(ppttrr - pOz->tlsconn))

typedef struct _tlsconn {
    unsigned char occupied;
    //
    int      type;
    //
    int      sockfd;
    int      pipefd[2];

    SSL_CTX *ctx;
    SSL     *ssl;
    BIO     *rbio; // SSL reads from, we write to.
    BIO     *wbio; // SSL writes to, we read from.

    char *pbuffer; //plain
    int   pbuffer_limit;
    int   pbuffer_len;

    int   total_read;
    int   total_write;
} tlsconn_t;

typedef struct _tlsmagic {
    pthread_mutex_t mutex;
    int             current;
    int             total;
    tlsconn_t       tlsconn[MAX_TLS_CONN_NUM];
    pthread_mutex_t connlock[MAX_TLS_LOCK_NUM];
} tlsmagic_t;

static tlsmagic_t   Oz;
static tlsmagic_t *pOz = &Oz;

///////////////////////////////////////////////////////
// function
///////////////////////////////////////////////////////
typedef void Sigfunc(int );

void sig_ignore(int signo) {
    /* too many... */
}

Sigfunc *sys_signal(int signo, Sigfunc *func)
{
    struct sigaction act, oact;
    act.sa_handler = func;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;

#ifdef SA_INTERRUPT
    act.sa_flags |= SA_INTERRUPT;
#endif

    act.sa_flags |= SA_RESTART;

    if (sigaction(signo, &act, &oact) < 0) {
        return (SIG_ERR);
    }
    return oact.sa_handler;
}

/**
 * lock
 */
int TLS_LOCK(const char *f) {
    LOGD("TLS_LOCK() - f: %s", f);

    int	error = pthread_mutex_lock(&pOz->mutex);
    if (error != 0) {
        LOGE("TLS_LOCK() - pthread_mutex_lock() - error: %s(%d)", strerror(error), error);
        return -1;
    }

    return error;
}

/**
 * unlock
 */
int TLS_UNLOCK(const char *f) {
    LOGD("TLS_UNLOCK() - f: %s", f);

    int	error = pthread_mutex_unlock(&pOz->mutex);
    if (error != 0) {
        LOGE("TLS_UNLOCK() - pthread_mutex_unlock() - error: %s(%d)", strerror(error), error);
        return -1;
    }

    return error;
}

int CONN___LOCK(tlsconn_t *p_tlsconn, const char *f) {
    int tlsconn_id = TLSCONN_ID(p_tlsconn);
    int lock_id    = tlsconn_id % MAX_TLS_LOCK_NUM;
    LOGD("CONN___LOCK() - f: %s, TLSCONN_ID(%d), LOCK_ID(%d)", f, tlsconn_id, lock_id);

    int	error = pthread_mutex_lock(pOz->connlock + lock_id);
    if (error != 0) {
        LOGE("CONN_LOCK() - pthread_mutex_lock() - error: %s(%d)", strerror(error), error);
        return -1;
    }

    return error;
}

int CONN_UNLOCK(tlsconn_t *p_tlsconn, const char *f) {
    int tlsconn_id = TLSCONN_ID(p_tlsconn);
    int lock_id    = tlsconn_id % MAX_TLS_LOCK_NUM;
    LOGD("CONN_UNLOCK() - f: %s, TLSCONN_ID(%d), LOCK_ID(%d)", f, tlsconn_id, lock_id);

    int	error = pthread_mutex_unlock(pOz->connlock + lock_id);
    if (error != 0) {
        LOGE("CONN_UNLOCK() - pthread_mutex_unlock() - error: %s(%d)", strerror(error), error);
        return -1;
    }

    return error;
}

int tlsmagic_initialize() {
    memset(pOz, 0x00, sizeof(tlsmagic_t));

    //전역 mutex를 초기화한다.
    if (common_mutex_init(&pOz->mutex) == -1) {
        LOGE("tlsmagic_initialize() - common_mutex_init(1) failed!");
        return -1;
    }

    //개별 mutex를 초기화한다.
    for (int i = 0; i < MAX_TLS_LOCK_NUM; i++) {
        if (common_mutex_init(&pOz->connlock[i]) == -1) {
            LOGE("tlsmagic_initialize() - common_mutex_init(2) failed!");
            //초기화 실패한 경우, 정상적인 구동이 불가능 하므로 별도의 자원 회수 없이 걍... go
            return -1;
        }
    }

    /* init openssl things!! */
    SSL_library_init();
    SSL_load_error_strings();
    ERR_load_BIO_strings();

    //TODO - ARIA 지원을 위해 필요한지는 확인 필요
    //OpenSSL_add_all_algorithms();

    return 0;
}

/**
 * allocate tlsconn..
 */
tlsconn_t *TLSCONN_ALLOC(int type, const char *f) {
    int start, current;
    tlsconn_t *p_tlsconn;

    LOGD("TLSCONN_ALLOC() - f: %s, type: %d", f, type);

    /* !!!!!!!!!!!!!!! LOCK HERE !!!!!!!!!!!!!!!!! */
    TLS_LOCK("TLSCONN_ALLOC()");
    LOGV("TLSCONN_ALLOC() - TLSCONN_ID(?) ... 1");

    /* save the current position */
    start = pOz->current;
    LOGV("TLSCONN_ALLOC() - TLSCONN_ID(?) ... 2");
    do {
        current   = pOz->current = pOz->current % MAX_TLS_CONN_NUM; pOz->current += 1;
        p_tlsconn = TLSCONN_PTR(current);
        if (!p_tlsconn->occupied) {
            memset(p_tlsconn, 0x00, sizeof(tlsconn_t));
            p_tlsconn->occupied  = 1;
            p_tlsconn->type      = type;
            p_tlsconn->sockfd    = -1; //소켓 초기화
            p_tlsconn->pipefd[0] = -1; //파이프 초기화
            p_tlsconn->pipefd[1] = -1; //파이프 초기화
            pOz->total += 1;

            /* !!!!!!!!!!!!!!! UNLOCK HERE !!!!!!!!!!!!!!!!! */
            TLS_UNLOCK("TLSCONN_ALLOC()");
            LOGD("TLSCONN_ALLOC() - TLSCONN_ID(%d), total: %d", TLSCONN_ID(p_tlsconn), pOz->total);

            return p_tlsconn;
        }
    }
    while (start != pOz->current);
    LOGV("TLSCONN_ALLOC() - TLSCONN_ID(?) ... 3");

    /* !!!!!!!!!!!!!!! UNLOCK HERE !!!!!!!!!!!!!!!!! */
    TLS_UNLOCK("TLSCONN_ALLOC()");
    LOGD("TLSCONN_ALLOC() - not available!, total: %d", pOz->total);

    return NULL;
}

/**
 * release tlsconn...
 */
void TLSCONN_FREE(int tlsconn_id, const char *f) {
    tlsconn_t *p_tlsconn;

    LOGD("TLSCONN_FREE() - f: %s, TLSCONN_ID(%d)", f, tlsconn_id);

    if (!TLSCONN_CHK(tlsconn_id)) {
        LOGE("TLSCONN_FREE() - invalid TLSCONN_ID(%d)", tlsconn_id);
        return;
    }

    /* !!!!!!!!!!!!!!! LOCK HERE !!!!!!!!!!!!!!!!! */
    LOGV("TLSCONN_FREE() - TLSCONN_ID(%d) ... 1", tlsconn_id);
    TLS_LOCK("TLSCONN_FREE()");

    //pointing..
    LOGV("TLSCONN_FREE() - TLSCONN_ID(%d) ... 2", tlsconn_id);
    p_tlsconn = TLSCONN_PTR(tlsconn_id);

    //occupied check!!
    LOGV("TLSCONN_FREE() - TLSCONN_ID(%d) ... 3", tlsconn_id);
    if (!p_tlsconn->occupied) {
        LOGE("TLSCONN_FREE() - unoccupied TLSCONN_ID(%d)", tlsconn_id);
        goto out;
    }

    /* BIO */
    LOGD("TLSCONN_FREE() - TLSCONN_ID(%d) ... 4", tlsconn_id);
//    if (p_tlsconn->bio != NULL) {
//        //BIO_free_all(p_tlsconn->bio);
//        p_tlsconn->bio = NULL;
//    }

    CONN___LOCK(p_tlsconn, "TLSCONN_FREE");

    /* SSL */
    LOGV("TLSCONN_FREE() - TLSCONN_ID(%d) ... 5", tlsconn_id);
    if (p_tlsconn->ssl != NULL) {
        SSL_shutdown(p_tlsconn->ssl);
        SSL_free(p_tlsconn->ssl);
        p_tlsconn->ssl = NULL;
    }

    CONN_UNLOCK(p_tlsconn, "TLSCONN_FREE");

    /* SSL_CTX */
    LOGV("TLSCONN_FREE() - TLSCONN_ID(%d) ... 6", tlsconn_id);
    if (p_tlsconn->ctx != NULL) {
        SSL_CTX_free(p_tlsconn->ctx);
        p_tlsconn->ctx = NULL;
    }

    /* socket fd */
    LOGV("TLSCONN_FREE() - TLSCONN_ID(%d) ... 7", tlsconn_id);
    if (p_tlsconn->sockfd != -1) {
        close(p_tlsconn->sockfd);
        p_tlsconn->sockfd = -1;
    }

    /* pipe */
    LOGV("TLSCONN_FREE() - TLSCONN_ID(%d) ... 8", tlsconn_id);
    if (p_tlsconn->pipefd[0] != -1) {
        close(p_tlsconn->pipefd[0]);
        p_tlsconn->pipefd[0] = -1;
    }
    if (p_tlsconn->pipefd[1] != -1) {
        close(p_tlsconn->pipefd[1]);
        p_tlsconn->pipefd[1] = -1;
    }

    /* pbuffer */
    LOGV("TLSCONN_FREE() - TLSCONN_ID(%d) ... 9", tlsconn_id);
    if (p_tlsconn->pbuffer != NULL) {
        free(p_tlsconn->pbuffer);
        p_tlsconn->pbuffer = NULL;
    }
    p_tlsconn->pbuffer_limit = 0;
    p_tlsconn->pbuffer_len   = 0;

    /* UNOCCUPY!! */
    LOGV("TLSCONN_FREE() - TLSCONN_ID(%d) ... 10", tlsconn_id);
    p_tlsconn->occupied = 0;
    pOz->total -= 1;

out:

    LOGV("TLSCONN_FREE() - TLSCONN_ID(%d) ... 11", tlsconn_id);

    /* !!!!!!!!!!!!!!! UNLOCK HERE !!!!!!!!!!!!!!!!! */
    TLS_UNLOCK("TLSCONN_FREE()");
    LOGD("TLSCONN_FREE() - TLSCONN_ID(%d), total: %d", tlsconn_id, pOz->total);

    return;
}

#define S_FAILED   -1
#define S_UNKNOWN  -2
#define S_DOAGAIN   0
#define S_SHUTDOWN  1
#define S_WAKEUP    2
static int proc_signal(int pipefd) {
    unsigned char byte;

    LOGD("proc_signal() - pipefd: %d", pipefd);

    if (read(pipefd, &byte, 1) == -1) {
        LOGE("proc_signal() - fail to read() - error: %s(%d)", strerror(errno), errno);
        if (errno == EINTR) {
            return S_DOAGAIN;
        }
        return S_FAILED;
    }

    return byte;
}

/**
 * readable
 */
static int is_readable(tlsconn_t *p_tlsconn, int timeo) {
    fd_set fdset;
    struct timeval tv;
    int maxfd, sockfd, pipefd;
    int cc;

    LOGD("is_readable() - TLSCONN_ID(%d), timeo: %d", TLSCONN_ID(p_tlsconn), timeo);
    if (p_tlsconn == NULL || p_tlsconn->sockfd == -1) {
        LOGE("is_readable() - invalid sockfd");
        return -1;
    }
    sockfd = p_tlsconn->sockfd;
    pipefd = p_tlsconn->pipefd[0];

again:

    //event
    FD_ZERO(        &fdset);
    FD_SET (sockfd, &fdset);
    if (pipefd != -1) {
        FD_SET(pipefd, &fdset);
        maxfd = (sockfd > pipefd) ? sockfd : pipefd;
    }
    else {
        maxfd = sockfd;
    }
    LOGD("is_readable() - TLSCONN_ID(%d), maxfd: %d, sockfd: %d, pipefd: %d", TLSCONN_ID(p_tlsconn), maxfd, sockfd, pipefd);

    //timeout
    tv.tv_sec  = (timeo / 1000);
    tv.tv_usec = (timeo % 1000) * 1000;

    /* BLOCK HERE! */
    if ((cc = select(maxfd+1, &fdset, NULL, NULL, (timeo == 0) ? NULL : &tv)) == -1) {
        if (errno == EINTR) {
            goto again;
        }
    }
    else if (cc == 0) {
        errno = ETIMEDOUT;
    }
    else {
        //signal을 수신한 경우,
        if (pipefd != -1 && FD_ISSET(pipefd, &fdset)) {
            int command = proc_signal(pipefd);
            LOGD("is_readable() - tls_signal has come! - command: %d", command);
            if (command == S_DOAGAIN) {
                goto again;
            }
            else if (command == S_FAILED) {
                return -1;
            }
            else if (command == S_WAKEUP) {
                return -1;
            }
            else if (command == S_SHUTDOWN) {
                return -1;
            }
            else { // S_UNKNOWN
                return -1;
            }
        }
    }

    return cc;
}

/**
 * writable
 */
static int is_writable(int fd, int timeo) {
    fd_set fdset;
    struct timeval tv;
    int cc;

    LOGD("is_writable() - fd: %d, timeo: %d", fd, timeo);
    if (fd == -1) {
        LOGE("is_writable() - invalid fd: %d", fd);
        return -1;
    }

again:

    //event
    FD_ZERO(    &fdset);
    FD_SET (fd, &fdset);

    //timeout
    tv.tv_sec  = (timeo / 1000);
    tv.tv_usec = (timeo % 1000) * 1000;

    /* BLOCK HERE! */
    if ((cc = select(fd+1, NULL, &fdset, NULL, (timeo == 0) ? NULL : &tv)) == -1) {
        if (errno == EINTR) {
            goto again;
        }
    }
    else if (cc == 0) {
        errno = ETIMEDOUT;
    }

    return cc;
}

/**
 * connect
 */
int setup_remote_address(const char *host, int port, sockaddr_in *remote) {
    struct hostent *hp;
    in_addr_t address;

    LOGD("setup_remote_address() - host: %s, port: %d", host, port);

    if ((address = inet_addr(host)) == (in_addr_t)-1) {
        if ((hp = gethostbyname(host)) == NULL) {
            LOGE("setup_remote_address() - fail to gethostbyname(%s) - error: %s(%d)",
                 host, strerror(errno), errno);
            return -1;
        }
        if(*hp->h_addr_list == NULL ) {
            LOGE("tcp_connect() - invalid host(%s) - error: %s(%d)", host, strerror(errno), errno);
            return -1;
        }
        address = *(in_addr_t *)*hp->h_addr_list;
    }

    remote->sin_family = AF_INET;
    remote->sin_addr.s_addr = address;
    remote->sin_port = htons(port);

    LOGD("set_server_address() - host:%s, address: %s, port: %d",
         host, inet_ntoa(remote->sin_addr), port);

    return 0;
}

int setup_socket_option(int fd, int bufsize, int nonblock) {
    struct linger lng;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (char *)&bufsize, sizeof(bufsize)) == -1) {
        LOGE("setup_socket_option() - setsockopt(SO_SNDBUF) - bufsize: %d, error: %s(%d)",
             bufsize, strerror(errno), errno);
        return -1;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (char *)&bufsize, sizeof(bufsize)) == -1) {
        LOGE("setup_socket_option() - setsockopt(SO_RCVBUF) - bufsize: %d, error: %s(%d)",
             bufsize, strerror(errno), errno);
        return -1;
    }
    lng.l_onoff = nonblock; lng.l_linger = 0;
    if (setsockopt(fd, SOL_SOCKET, SO_LINGER, (char *) &lng, sizeof(lng)) == -1) {
        LOGE("setup_socket_option() - setsockopt(SO_LINGER) - bufsize: %d, error: %s(%d)",
             bufsize, strerror(errno), errno);
        return -1;
    }

    return 0;
}

int tcp_connect_timeo(const char *host, int port, int timeo) {
    struct sockaddr_in dst_addr, src_addr; // for local socket address
    int sockfd, saved, cc;

    LOGD("tcp_connect_timeo() - host: %s, port: %d, timeo: %d",
         (host != NULL ? host : "null"), port, timeo);

    memset((char *)&dst_addr, 0x00, sizeof(struct sockaddr_in));
    memset((char *)&src_addr, 0x00, sizeof(struct sockaddr_in));

    //remote setup..
    if ((cc = setup_remote_address(host, port, &dst_addr)) == -1) {
        LOGE("tcp_connect_timeo() - fail to setup_remote_address() - cc: %d, host: %s, error: %s(%d)",
             cc, host, strerror(errno), errno);
        return -1;
    }

    //create socket
    if ((sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
        LOGD("tcp_connect_timeo() - fail to socket() - fd: %d, error: %s(%d)",
             sockfd, strerror(errno), errno);
        return -1;
    }

    //setup socket option (에러는 개무시!!)
    setup_socket_option(sockfd, 32*1024, 1);

    //non-block 설정
    saved = fcntl(sockfd, F_GETFL, 0);
    if ((cc = fcntl(sockfd, F_SETFL, saved | O_NONBLOCK)) == -1) {
        LOGE("tcp_connect_timeo() - fail to fcntl(O_NONBLOCK) - cc: %d, error: %s(%d)",
             cc, strerror(errno), errno);
        close(sockfd);
        return -1;
    }

    //connect
    if (connect(sockfd, (struct sockaddr *)&dst_addr, sizeof(dst_addr)) == -1) {
        if (errno != EINPROGRESS) {
            LOGE("tcp_connect_timeo() - fail to connect() - error: %s(%d)", strerror(errno), errno);
            close(sockfd);
            return -1;
        }
    }

    //check if connected
    if ((cc = is_writable(sockfd, timeo)) == -1 || cc == 0) { // -1:error, 0:timeout
        LOGE("tcp_connect_timeo() - fail to is_writable() - error: %s(%d)", strerror(errno), errno);
        close(sockfd);
        return -1;
    }

    //복구한다...
    //fcntl(sockfd, F_SETFL, saved);

    LOGD("tcp_connect_timeo() - cc: %d, sockfd: %d", cc, sockfd);

    return sockfd;
}

int tls_handshake_timeo(tlsconn_t *p_tlsconn, int timeo) {
    char buf[128];
    int sockfd = p_tlsconn->sockfd;
    int cc, err, n;

    LOGD("tls_handshake_timeo() - timeo: %d", timeo);

again:

    cc  = SSL_connect(p_tlsconn->ssl);
    err = SSL_get_error(p_tlsconn->ssl, cc);
    LOGD("tls_handshake_timeo() - SSL_connect() - cc: %d, err: %d, errno: %d, %s",
         cc,
         err,
         errno,
         ERR_error_string(ERR_get_error(), NULL));
    if (cc <= 0) {
        if (err == SSL_ERROR_WANT_READ) {
            if (is_readable(p_tlsconn, timeo) > 0) {
                goto again;
            }
        }
        else if (err == SSL_ERROR_WANT_WRITE) {
            if (is_writable(sockfd, timeo) > 0) {
                goto again;
            }
        }
        else {
            LOGD("tls_handshake_timeo() - SSL_connect() - failed!");
        }
        //에러 반환
        cc = -1;
    }

    return cc;
}

/**
 * certificate
 */
int tls_init_x509_store(SSL_CTX *ctx, char *cert, int cert_len) {
    LOGD("tls_init_x509_store() - cert ------------------\n%s\n", cert);

    BIO *cbio = BIO_new_mem_buf((void*)cert, (int)cert_len);
    X509_STORE *cts = SSL_CTX_get_cert_store(ctx);
    if (!cts || !cbio) {
        return 0;
    }
    X509_INFO *itmp;
    int i, count = 0, type = X509_FILETYPE_PEM;
    STACK_OF(X509_INFO) *inf = PEM_X509_INFO_read_bio(cbio, NULL, NULL, NULL);

    if (!inf) {
        BIO_free(cbio);//cleanup
        return 0;
    }

//itterate over all entries from the pem file, add them to the x509_store one by one
    for (i = 0; i < sk_X509_INFO_num(inf); i++) {
        itmp = sk_X509_INFO_value(inf, i);
        if (itmp->x509) {
            X509_STORE_add_cert(cts, itmp->x509);
            count++;
        }
        if (itmp->crl) {
            X509_STORE_add_crl(cts, itmp->crl);
            count++;
        }
    }
    sk_X509_INFO_pop_free(inf, X509_INFO_free); //cleanup
    BIO_free(cbio);//cleanup

    return 1;
}

static int tls_verify_result(SSL *ssl, const char *host) {
    X509 *peer;
    char peer_CN[256];
    int cc;

    LOGD("tls_verify_result() - host: %s", host);

    if ((cc = SSL_get_verify_result(ssl)) != X509_V_OK) {
        LOGE("tls_verify_result() - fail to SSL_get_verify_result() - cc: %d, %s",
             cc, ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }

    /*Check the cert chain. The chain length
      is automatically checked by OpenSSL when
      we set the verify depth in the ctx */
    /*Check the common name*/
    if ((peer = SSL_get_peer_certificate(ssl)) != NULL) {
        X509_NAME_get_text_by_NID(X509_get_subject_name(peer), NID_commonName, peer_CN, 256);
    }
    LOGD("tls_verify_result() - host: %s, peer_CN: %s", host, (peer_CN != NULL ? peer_CN : "null"));

    return 0;
}

static const char *ssl_msg_type(int major, int msg) {
    if (major == SSL3_VERSION_MAJOR) {
        switch (msg) {
            case SSL3_MT_HELLO_REQUEST: return "Hello request";
            case SSL3_MT_CLIENT_HELLO: return "Client hello";
            case SSL3_MT_SERVER_HELLO: return "Server hello";
            case SSL3_MT_NEWSESSION_TICKET: return "Newsession Ticket";
            case SSL3_MT_CERTIFICATE: return "Certificate";
            case SSL3_MT_SERVER_KEY_EXCHANGE: return "Server key exchange";
            case SSL3_MT_CLIENT_KEY_EXCHANGE: return "Client key exchange";
            case SSL3_MT_CERTIFICATE_REQUEST: return "Request CERT";
            case SSL3_MT_SERVER_DONE: return "Server finished";
            case SSL3_MT_CERTIFICATE_VERIFY: return "CERT verify";
            case SSL3_MT_FINISHED: return "Finished";
            case SSL3_MT_CERTIFICATE_STATUS: return "Certificate Status";
        }
    }
    return "Unknown";
}

static const char *tls_rt_type(int type) {
    switch(type) {
        case SSL3_RT_HEADER: return "TLS header";
        case SSL3_RT_CHANGE_CIPHER_SPEC: return "TLS change cipher";
        case SSL3_RT_ALERT: return "TLS alert";
        case SSL3_RT_HANDSHAKE: return "TLS handshake";
        case SSL3_RT_APPLICATION_DATA: return "TLS app data";
        default: return "TLS Unknown";
    }
}

static const char *tls_version(int version) {
    switch (version) {
        case SSL2_VERSION  : return "SSLv2";
        case SSL3_VERSION  : return "SSLv3";
        case TLS1_VERSION  : return "TLSv1.0";
        case TLS1_1_VERSION: return "TLSv1.1";
        case TLS1_2_VERSION: return "TLSv1.2";
        case TLS1_3_VERSION: return "TLSv1.3";
        default: return "UNK";
    }
}

static void ssl_tls_trace(int direction, int ssl_ver, int content_type,
                          const void *buf, size_t len, SSL *ssl, void *userp)
{
    const char *msg_name, *tls_rt_name;
    const char *verstr;
    int  msg_type;
    int  major;

    verstr = tls_version(ssl_ver);

    /* the info given when the version is zero is not that useful for us */
    major = ssl_ver >> 8; /* check the upper 8 bits only below */

    /* SSLv2 doesn't seem to have TLS record-type headers, so OpenSSL
     * always pass-up content-type as 0. But the interesting message-type
     * is at 'buf[0]'.
     */
    if (major == SSL3_VERSION_MAJOR && content_type) {
        tls_rt_name = tls_rt_type(content_type);
    }
    else {
        tls_rt_name = "";
    }
    msg_type = *(char*)buf;
    msg_name = ssl_msg_type(major, msg_type);

    LOGI("!!!TRACE!!! %s %s(0x%x) | %s, %s (%d)",
         direction ? "<-" : "->",
         verstr,
         ssl_ver,
         tls_rt_name,
         msg_name,
         msg_type);
}

/**
 * SSL_CTX init
 */
static SSL_CTX *tls_init_ctx(char *cert, int cert_len, int tls_v1_3_flag) {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    LOGD("tls_init_ctx()");

    //Create SSL_CTX
    if ((method = TLS_client_method()) == NULL) {
        LOGE("tls_init_ctx() - fail to TLS_client_method() - sslerror: %s",
             ERR_error_string(ERR_get_error(), NULL));
        return NULL;
    }
    if ((ctx = SSL_CTX_new(method)) == NULL) {
        LOGE("tls_init_ctx() - fail to SSL_CTX_new() - sslerror: %s",
             ERR_error_string(ERR_get_error(), NULL));
        return NULL;
    }

    //TLS handshake debug.
    SSL_CTX_set_msg_callback(ctx, ssl_tls_trace);

    //TLS min/max Version (TLSv1.3)
    if (tls_v1_3_flag) {
        if (SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) != 1) {
            LOGE("tls_init_ctx() - fail to SSL_CTX_set_min_proto_version() - sslerror: %s",
                 ERR_error_string(ERR_get_error(), NULL));
        }
        if (SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) != 1) {
            LOGE("tls_init_ctx() - fail to SSL_CTX_set_max_proto_version() - sslerror: %s",
                 ERR_error_string(ERR_get_error(), NULL));
        }
    }

    //인증서 로드 (파일이 아닌 byte Array를 주입)
    //tls_init_x509_store(ctx, cert, cert_len);

    //SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
    //TODO SSL 인증 설정 (서버 TLS 구성 완료시, 아래 주석을 풀것!)
    //SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    //상호 인증을 위한 코드 (단말은 단일 인증이므로 pass)
    //SSL_CTX_set_verify_depth(ctx, 1);
    //TODO cipher suites 선택을 위한 코드
    //SSL_CTX_set_cipher_list(ctx, "ARIA");

    return ctx;
}

static int tls_get_myaddress(int sockfd, char *local_ip, int ip_len) {
    struct sockaddr_in my_addr;

    memset(&my_addr, 0x00, sizeof(my_addr));
    socklen_t len = sizeof(my_addr);
    getsockname(sockfd, (struct sockaddr *)&my_addr, &len);
    inet_ntop(AF_INET, &my_addr.sin_addr, local_ip, ip_len);

    return 0;
}

long bio_dump_callback(BIO *bio, int cmd, const char *argp, int argi, long argl, long ret) {
    if (cmd == (BIO_CB_READ | BIO_CB_RETURN)) {
        LOGV("read from %p [%p] (%lu bytes => %ld (0x%lX))\n",
                   (void *)bio, (void *)argp, (unsigned long)argi, ret, ret);
        BIO_dump_fp(stderr, argp, (int)ret);
    }
    else if (cmd == (BIO_CB_WRITE | BIO_CB_RETURN)) {
        LOGV("write to %p [%p] (%lu bytes => %ld (0x%lX))\n",
                   (void *)bio, (void *)argp, (unsigned long)argi, ret, ret);
        BIO_dump_fp(stderr, argp, (int)ret);
    }

    return ret;
}

int tls_ssl_connect(tlsconn_t *p_tlsconn, const char *host, int port, int timeo) {
    int cc;

    LOGD("tls_ssl_connect() - host: %s, port: %d, timeo: %d", host, port, timeo);

    //TCP connnect..
    if ((p_tlsconn->sockfd = tcp_connect_timeo(host, port, timeo)) == -1) {
        LOGE("tls_ssl_connect() - fail to tcp_connect_timeo() - sockfd: %d, %s",
             p_tlsconn->sockfd, ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }

    //SSL 생성 및 SSL에 socket 연결
    p_tlsconn->ssl = SSL_new(p_tlsconn->ctx);
    if (p_tlsconn->ssl == NULL) {
        LOGE("tls_ssl_connect() - fail to SSL_new() - %s",
             ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }
    SSL_set_fd(p_tlsconn->ssl, p_tlsconn->sockfd);
    SSL_set_connect_state(p_tlsconn->ssl);

    //SSL Handshake를 시도한다.
    if ((cc = tls_handshake_timeo(p_tlsconn, timeo)) == -1) {
        LOGE("tls_ssl_connect() - fail to tls_handshake_timeo() - cc: %d, %s",
             cc, ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }

    //SSL Handshake 이후, 메모리 BIO를 SSL에 연결
    p_tlsconn->rbio = BIO_new(BIO_s_mem());
    p_tlsconn->wbio = BIO_new(BIO_s_mem());
    SSL_set_bio(p_tlsconn->ssl, p_tlsconn->rbio, p_tlsconn->wbio);

    BIO_set_callback(p_tlsconn->rbio, bio_dump_callback);
    BIO_set_callback(p_tlsconn->wbio, bio_dump_callback);

    //소켓 제어를 위해 pipe를 생성한다.
    if ((cc = pipe(p_tlsconn->pipefd)) == -1) {
        LOGE("tls_ssl_connect() - fail to pipe() - cc: %d, %s(%d)", cc, strerror(errno), errno);
        return -1;
    }

    return 0;
}

/**
 * open
 */
int tls_open(int type, const char *host, int port, char *cert, int cert_len, char *local_ip, int ip_len, int timeo) {
    int cc;

    tlsconn_t *p_tlsconn = NULL;
    int        tlsconn_id = -1;

    /* SIGPIPE */
    LOGD("tls_open() - TLSCONN_ID(?|?) ... 1");
    sys_signal(SIGPIPE, sig_ignore);

    //allocate tlsconn
    LOGD("tls_open() - TLSCONN_ID(?|?) ... 2");
    if ((p_tlsconn = TLSCONN_ALLOC(type, "tls_open()")) == NULL) {
        LOGE("tls_open() - fail to tlsconn_alloc()");
        return -1;
    }
    tlsconn_id = TLSCONN_ID(p_tlsconn);

    //SSL_CTX
    LOGD("tls_open() - TLSCONN_ID(%d|%d) ... 3", tlsconn_id, p_tlsconn->type);
    if ((p_tlsconn->ctx = tls_init_ctx(cert, cert_len, 0)) == NULL) {
        LOGE("tls_open() - fail to tls_init_ctx()");
        TLSCONN_FREE(TLSCONN_ID(p_tlsconn), "tls_open()");
        return -1;
    }

    //connect + handshake..
    LOGD("tls_open() - TLSCONN_ID(%d|%d) ... 4", tlsconn_id, p_tlsconn->type);
    if ((cc = tls_ssl_connect(p_tlsconn, host, port, timeo)) == -1) {
    //if ((cc = tls_bio_connect(p_tlsconn, host, port, timeo)) == -1) {
        LOGE("tls_open() - fail to tls_connect() - cc: %d", cc);
        TLSCONN_FREE(TLSCONN_ID(p_tlsconn), "tls_open()");
        return -1;
    }

    // certificate check
    LOGD("tls_open() - TLSCONN_ID(%d|%d) ... 5", tlsconn_id, p_tlsconn->type);
    if ((cc = tls_verify_result(p_tlsconn->ssl, host)) == -1) {
        LOGE("tls_open() - fail to SSL_get_verify_result() - cc: %d, %s",
             cc, ERR_error_string(ERR_get_error(), NULL));
        TLSCONN_FREE(TLSCONN_ID(p_tlsconn), "tls_open()");
        return -1;
    }

    /* local address... */
    LOGD("tls_open() - TLSCONN_ID(%d|%d) ... 6", tlsconn_id, p_tlsconn->type);
    if ((cc = tls_get_myaddress(p_tlsconn->sockfd, local_ip, ip_len)) == -1) {
        LOGE("tls_open() - fail to tls_get_myaddress() - cc: %d", cc);
        TLSCONN_FREE(TLSCONN_ID(p_tlsconn), "tls_open()");
        return -1;
    }

    LOGD("tls_open() - TLSCONN_ID(%d|%d) is allocated!", tlsconn_id, p_tlsconn->type);

    return TLSCONN_ID(p_tlsconn);
}

int tls_signal(int tlsconn_id, unsigned char byte) {
    tlsconn_t *p_tlsconn;
    int sigfd;
    int cc;

    LOGD("tls_signal() - TLSCONN_ID(%d|?) ... 1", tlsconn_id);
    if (!TLSCONN_CHK(tlsconn_id)) {
        LOGE("tls_shutdown() - TLSCONN_ID(%d), invalid!", tlsconn_id);
        return -1;
    }

    //pointing..
    LOGD("tls_signal() - TLSCONN_ID(%d|?) ... 2", tlsconn_id);
    p_tlsconn = TLSCONN_PTR(tlsconn_id);
    if (!p_tlsconn->occupied) {
        LOGE("tls_signal() - TLSCONN_ID(%d), occupied: %d", tlsconn_id, p_tlsconn->occupied);
        return -1;
    }

    LOGD("tls_signal() - TLSCONN_ID(%d|%d) ... 3", tlsconn_id, p_tlsconn->type);
    if ((sigfd = p_tlsconn->pipefd[1]) == -1) {
        LOGE("tls_signal() - TLSCONN_ID(%d), invalid pipefd[1] ... %d", tlsconn_id, sigfd);
        return -1;
    }

    LOGD("tls_signal() - TLSCONN_ID(%d|%d) ... 5", tlsconn_id, p_tlsconn->type);
    if ((cc = write(sigfd, &byte, 1)) != 1) {
        LOGE("tls_signal() - TLSCONN_ID(%d|%d), write() returns %d, error: %s(%d)",
             tlsconn_id, p_tlsconn->type, cc, strerror(errno), errno);
        return -1;
    }

    return 0;
}

/**
 * close
 */
int tls_close(int tlsconn_id) {
    LOGD("tls_close() - TLSCONN_ID(%d)", tlsconn_id);

    //release tlsconn
    TLSCONN_FREE(tlsconn_id, "tls_close()");
    LOGD("tls_close() - TLSCONN_ID(%d) ... 1", tlsconn_id);

    return 0;
}

/**
 * 소켓으로 부터 읽기를 시도 및 복호화
 * @param p_tlsconn
 * @param timeo
 * @return 0 > 성공; -2 이면 타임아웃; -1이면 에러; 0 이면 EOF
 */
int tls_read_loop(tlsconn_t *p_tlsconn, int timeo) {
    char cbuffer[2048];
    char part[2048];
    int  tlsconn_id = TLSCONN_ID(p_tlsconn);
    int  sockfd;
    int  err;

    do {
        LOGD("tls_read_loop() - TLSCONN_ID(%d|%d) ... 1", tlsconn_id, p_tlsconn->type);
        if (p_tlsconn->sockfd == -1) {
            LOGE("tls_read_loop() - invalid sockfd - TLSCONN_ID(%d)", tlsconn_id);
            return -1;
        }

        LOGD("tls_read_loop() - TLSCONN_ID(%d|%d) ... 2-1", tlsconn_id, p_tlsconn->type);
        int readable = is_readable(p_tlsconn, timeo);
        LOGD("tls_read_loop() - TLSCONN_ID(%d|%d) ... 2-2, readable: %d", tlsconn_id, p_tlsconn->type, readable);
        if (readable == -1) { //에러
            LOGE("tls_read_loop() - TLSCONN_ID(%d), is_readable() returns %d, error: %s(%d)",
                 tlsconn_id, readable, strerror(errno), errno);
            return -1;
        }
        else if (readable == 0) { //타임아웃
            LOGE("tls_read_loop() - TLSCONN_ID(%d), is_readable() returns %d, error: %s(%d)",
                 tlsconn_id, readable, strerror(errno), errno);
            return -2;
        }

        LOGD("tls_read_loop() - TLSCONN_ID(%d|%d) ... 3", tlsconn_id, p_tlsconn->type);
        if ((sockfd = p_tlsconn->sockfd) == -1) {
            LOGE("tls_read_loop() - TLSCONN_ID(%d), already socket closed! sockfd: %d",
                 tlsconn_id, sockfd);
            return -1;
        }

        //암호화된 패킷을 읽어온다.
        LOGD("tls_read_loop() - TLSCONN_ID(%d|%d) ... 4-1", tlsconn_id, p_tlsconn->type);
        int sock_read_len = read(sockfd, cbuffer, sizeof(cbuffer));
        LOGD("tls_read_loop() - TLSCONN_ID(%d|%d) ... 4-2, sock_read_len: %d", tlsconn_id, p_tlsconn->type, sock_read_len);
        if (sock_read_len == -1) {
            LOGE("tls_read_loop() - TLSCONN_ID(%d|%d), 4-3-1, read() returns %d, error: %s(%d)",
                 tlsconn_id, p_tlsconn->type, sock_read_len, strerror(errno), errno);
            if (errno == EINTR) {
                LOGI("tls_read_loop() - TLSCONN_ID(%d|%d), 4-3-2, read() Interrupted!", tlsconn_id, p_tlsconn->type);
                continue;
            }
            else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                LOGI("tls_read_loop() - TLSCONN_ID(%d|%d), 4-3-3, read() WOULDBLOCKED!", tlsconn_id, p_tlsconn->type);
                continue;
            }
            return sock_read_len;
        }
        else if (sock_read_len == 0) {
            LOGE("tls_read_loop() - TLSCONN_ID(%d|%d), 4-3-4, read() returns %d, error: %s(%d)",
                 tlsconn_id, p_tlsconn->type, sock_read_len, strerror(errno), errno);
            return 0;
        }

        // BIO_write는 source 메모리의 내용을 복호화하여 연결한 SSL에서 읽을 수 있도록 한다.
        LOGD("tls_read_loop() - TLSCONN_ID(%d|%d) ... 5-1", tlsconn_id, p_tlsconn->type);

        CONN___LOCK(p_tlsconn, "tls_read_loop(1-1)");
        if (p_tlsconn->ssl == NULL) {
            CONN_UNLOCK(p_tlsconn, "tls_read_loop(1-2)");
            LOGD("tls_read_loop() - TLSCONN_ID(%d|%d) ... 5-2, SSL is NULL!", tlsconn_id, p_tlsconn->type);
            return -1;
        }

        int rbio_written_len = BIO_write(p_tlsconn->rbio, cbuffer, sock_read_len);
        LOGD("tls_read_loop() - TLSCONN_ID(%d|%d) ... 5-3, rbio_written_len: %d", tlsconn_id,
             p_tlsconn->type, rbio_written_len);
        if (rbio_written_len <= 0) {
            CONN_UNLOCK(p_tlsconn, "tls_read_loop(1-2)");
            LOGE("tls_read_loop() - TLSCONN_ID(%d|%d) - 5-4, BIO_write() returns %d, %s",
                 tlsconn_id, p_tlsconn->type, rbio_written_len,
                 ERR_error_string(ERR_get_error(), NULL));
            return -1;
        }

        // 복호화 결과를 버퍼에 담아 반환한다.
        LOGD("tls_read_loop() - TLSCONN_ID(%d|%d) ... 6-1", tlsconn_id, p_tlsconn->type);
        int ssl_read_len = 0;
        while ((ssl_read_len = SSL_read(p_tlsconn->ssl, part, sizeof(part))) > 0) {
            //메모리를 할당한다.
            if (p_tlsconn->pbuffer_len + ssl_read_len > p_tlsconn->pbuffer_limit) {
                p_tlsconn->pbuffer_limit = p_tlsconn->pbuffer_len + ssl_read_len;
                if (p_tlsconn->pbuffer == NULL) {
                    p_tlsconn->pbuffer = (char *) malloc(p_tlsconn->pbuffer_limit);
                }
                else {
                    p_tlsconn->pbuffer = (char *) realloc(p_tlsconn->pbuffer, p_tlsconn->pbuffer_limit);
                }
            }
            //내부 공간에 저장한다.
            memcpy(p_tlsconn->pbuffer + p_tlsconn->pbuffer_len, part, ssl_read_len);
            p_tlsconn->pbuffer_len += ssl_read_len;

            //디버그...
            LOGD("tls_read_loop() - TLSCONN_ID(%d|%d) ... 6-2, pbuffer_len: %d, ssl_read_len: %d",
                 tlsconn_id, p_tlsconn->type, p_tlsconn->pbuffer_len, ssl_read_len);
        }
        err = SSL_get_error(p_tlsconn->ssl, ssl_read_len);
        LOGD("tls_read_loop() - TLSCONN_ID(%d|%d) ... 6-3, pbuffer_len: %d/%d, cc: %d, err: %d, ",
             tlsconn_id, p_tlsconn->type, p_tlsconn->pbuffer_len, p_tlsconn->pbuffer_limit,
             ssl_read_len, err);

        if (ssl_read_len <= 0) {
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                //again! but is pbuffer available? not now!!
                ;
            } else if (err == SSL_ERROR_ZERO_RETURN) {
                //stop! but is pbuffer available?
                ;
            } else {
                //oops!
                CONN_UNLOCK(p_tlsconn, "tls_read_loop(2-2)");
                LOGE("tls_read_loop() - TLSCONN_ID(%d|%d) ... 6-4, SSL_read() returns %d, %s",
                     tlsconn_id, p_tlsconn->type, ssl_read_len,
                     ERR_error_string(ERR_get_error(), NULL));
                return -1;
            }
        }
        CONN_UNLOCK(p_tlsconn, "tls_read_loop(2-3)");
    }
    while (p_tlsconn->pbuffer_len <= 0);

    return p_tlsconn->pbuffer_len;
}

int tls_copy(tlsconn_t *p_tlsconn, unsigned char *bytes, int len) {
    LOGD("tls_copy() - pbuffer_len: %d, bytes_len: %d", p_tlsconn->pbuffer_len, len);

    //copy..
    int min = (len <= p_tlsconn->pbuffer_len) ? len : p_tlsconn->pbuffer_len;
    memcpy(bytes, p_tlsconn->pbuffer, min);

    //total read length...
    p_tlsconn->total_read += min;

    //inline buffer
    p_tlsconn->pbuffer_len -= min;
    if (p_tlsconn->pbuffer_len > 0) {
        memmove(p_tlsconn->pbuffer, p_tlsconn->pbuffer + min, p_tlsconn->pbuffer_len);
    }

    return min;
}

/**
 * 읽은 데이타를 반환한다.
 * @param tlsconn_id
 * @param bytes
 * @param len
 * @param timeo
 * @return 0 > 성공; -2 이면 타임아웃; -1이면 에러; 0 이면 EOF
 */
int tls_read(int tlsconn_id, unsigned char *bytes, int len, int timeo) {
    tlsconn_t *p_tlsconn;
    int result;
    int min1 = 0;
    int min2 = 0;

    LOGD("tls_read() - TLSCONN_ID(%d|?) ... 1", tlsconn_id);
    if (!TLSCONN_CHK(tlsconn_id)) {
        LOGE("tls_read() - TLSCONN_ID(%d), invalid!", tlsconn_id);
        return -1;
    }

    //pointing..
    LOGD("tls_read() - TLSCONN_ID(%d|?) ... 2", tlsconn_id);
    p_tlsconn = TLSCONN_PTR(tlsconn_id);
    if (!p_tlsconn->occupied) {
        LOGE("tls_read() - TLSCONN_ID(%d), occupied: %d", tlsconn_id, p_tlsconn->occupied);
        return -1;
    }

    //check and read from memory
    LOGD("tls_read() - TLSCONN_ID(%d|%d) ... 3", tlsconn_id, p_tlsconn->type);
    if (p_tlsconn->pbuffer != NULL && p_tlsconn->pbuffer_len > 0) {
        min1 = tls_copy(p_tlsconn, bytes, len);
        LOGD("tls_read() - TLSCONN_ID(%d|%d) ... 3-1, len: %d, min1: %d, total_read: %d",
             tlsconn_id, p_tlsconn->type, len, min1, p_tlsconn->total_read);
        return min1;
    }
//    if ((len-min1) == 0) {
//        return min1;
//    }

    //read from network
    LOGD("tls_read() - TLSCONN_ID(%d|%d) ... 4", tlsconn_id, p_tlsconn->type);
    if ((result = tls_read_loop(p_tlsconn, timeo)) <= 0) {
        LOGE("tls_read() - TLSCONN_ID(%d|%d) ... 4-1, tls_read_loop() returns... %d",
             tlsconn_id, p_tlsconn->type, result);
        return result;
    }

    //read from memory again....
    LOGD("tls_read() - TLSCONN_ID(%d|%d) ... 5", tlsconn_id, p_tlsconn->type);
    if (p_tlsconn->pbuffer != NULL && p_tlsconn->pbuffer_len > 0) {
        min2 = tls_copy(p_tlsconn, bytes+min1, len-min1);
    }
    LOGD("tls_read() - TLSCONN_ID(%d|%d) ... 5-1, len: %d, min2: %d, total_read: %d",
         tlsconn_id, p_tlsconn->type, (len-min1), min2, p_tlsconn->total_read);

    return min1 + min2;
}

int tls_write_loop(tlsconn_t *p_tlsconn, char *vptr, int len, int timeo) {
    int tlsconn_id = TLSCONN_ID(p_tlsconn);
    int nleft;
    char *ptr;

    ptr   = vptr;
    nleft = len;
    while (nleft > 0) {
        LOGD("tls_write_loop() - TLSCONN_ID(%d|%d) ... 1-1", tlsconn_id, p_tlsconn->type);
        int writable = is_writable(p_tlsconn->sockfd, timeo);
        LOGD("tls_write_loop() - TLSCONN_ID(%d|%d) ... 1-2, writable: %d", tlsconn_id, p_tlsconn->type, writable);
        if (writable <= 0) {
            LOGE("tls_write_loop() - TLSCONN_ID(%d|%d), is_writable() returns %d, error: %s(%d)",
                 tlsconn_id, p_tlsconn->type, writable, strerror(errno), errno);
            return writable;
        }

        LOGD("tls_write_loop() - TLSCONN_ID(%d|%d) ... 2", tlsconn_id, p_tlsconn->type);
        if (p_tlsconn->sockfd == -1) {
            LOGE("tls_write_loop() - TLSCONN_ID(%d|%d), already socket closed! sockfd: %d",
                 tlsconn_id, p_tlsconn->type, p_tlsconn->sockfd);
            return -1;
        }

        LOGD("tls_write_loop() - TLSCONN_ID(%d|%d) ... 3-1", tlsconn_id, p_tlsconn->type);
        int nwritten = write(p_tlsconn->sockfd, vptr, nleft);
        LOGD("tls_write_loop() - TLSCONN_ID(%d|%d) ... 3-2, nwritten: %d", tlsconn_id, p_tlsconn->type, nwritten);
        if (nwritten <= 0) {
            if (nwritten == -1 && errno == EINTR) {
                continue;
            }
            LOGE("tls_write_loop() - TLSCONN_ID(%d|%d), write() returns %d, error: %s(%d)",
                 tlsconn_id, p_tlsconn->type, nwritten, strerror(errno), errno);
            return (-1);
        }

        nleft -= nwritten;
        ptr   += nwritten;

        LOGD("tls_write_loop() - TLSCONN_ID(%d|%d) ... 4, nleft: %d", tlsconn_id, p_tlsconn->type, nleft);
    }

    return len;
}

/**
 * write
 */
int tls_write(int tlsconn_id, unsigned char *bytes, int len, int timeo) {
    char cbuffer[MAX_BUFFER_SIZE];
    tlsconn_t *p_tlsconn;
    SSL *ssl;

    LOGD("tls_write() - TLSCONN_ID(%d|?) ... 1, len: %d, timeo: %d", tlsconn_id, len, timeo);
    if (!TLSCONN_CHK(tlsconn_id)) {
        LOGE("tls_write() - invalid TLSCONN_ID(%d)", tlsconn_id);
        return -1;
    }

    //pointing..
    LOGD("tls_write() - TLSCONN_ID(%d|?) ... 2", tlsconn_id);
    p_tlsconn = TLSCONN_PTR(tlsconn_id);

    //SSL
    LOGD("tls_write() - TLSCONN_ID(%d|%d) ... 3", tlsconn_id, p_tlsconn->type);
    CONN___LOCK(p_tlsconn, "tls_write(1-1)");
    if ((ssl = p_tlsconn->ssl) == NULL) {
        CONN_UNLOCK(p_tlsconn, "tls_write(1-2)");
        LOGE("tls_write() - TLSCONN_ID(%d|%d), invalid SSL!", tlsconn_id, p_tlsconn->type);
        return -1;
    }

    // SSL_write는 source 메모리의 내용을 암호화하여 연결한 BIO 메모리에 기록한다.
    LOGD("tls_write() - TLSCONN_ID(%d|%d) ... 4-1", tlsconn_id, p_tlsconn->type);
    int ssl_written_len = SSL_write(ssl, bytes, len);
    LOGD("tls_write() - TLSCONN_ID(%d|%d) ... 4-2, ssl_written_len: %d", tlsconn_id, p_tlsconn->type, ssl_written_len);
    if (ssl_written_len <= 0) {
        CONN_UNLOCK(p_tlsconn, "tls_write(1-3)");
        LOGE("tls_write() - TLSCONN_ID(%d|%d), SSL_write() returns %d, %s",
             tlsconn_id, p_tlsconn->type, ssl_written_len, ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }

    // 암호화된 내용을 target 메모리에 복사한다.
    LOGD("tls_write() - TLSCONN_ID(%d|%d) ... 5-1", tlsconn_id, p_tlsconn->type);
    int wbio_read_len = BIO_read(p_tlsconn->wbio, cbuffer, sizeof(cbuffer));
    LOGD("tls_write() - TLSCONN_ID(%d|%d) ... 5-2, wbio_read_len: %d", tlsconn_id, p_tlsconn->type, wbio_read_len);
    if (wbio_read_len <= 0) {
        CONN_UNLOCK(p_tlsconn, "tls_write(1-4)");
        LOGE("tls_write() - TLSCONN_ID(%d), BIO_read() returns %d, %s",
             tlsconn_id, wbio_read_len, ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }
    CONN_UNLOCK(p_tlsconn, "tls_write(1-5)");

    //network에 write한다.
    LOGD("tls_write() - TLSCONN_ID(%d|%d) ... 6-1", tlsconn_id, p_tlsconn->type);
    int sock_written_len = tls_write_loop(p_tlsconn, cbuffer, wbio_read_len, timeo);
    LOGD("tls_write() - TLSCONN_ID(%d|%d) ... 6-2, sock_written_len: %d", tlsconn_id, p_tlsconn->type, sock_written_len);
    if (sock_written_len <= 0) {
        LOGE("tls_write() - TLSCONN_ID(%d|%d), write() returns %d, errno: %s(%d), %s",
             tlsconn_id, p_tlsconn->type, sock_written_len, strerror(errno), errno, ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }

    LOGD("tls_write() - TLSCONN_ID(%d|%d) ... 7", tlsconn_id, p_tlsconn->type);

    return len;
}


///////////////////////////////////////////////////////
//
// JNI code..
//
///////////////////////////////////////////////////////
JNIEXPORT jint JNICALL
Java_com_kodeholic_httpswithopenssl_lib_jni_TLSNativeIF_tlsmagic_1initialize(JNIEnv *env, jclass type) {
    LOGD("tlsmagic_initialize()");
    return tlsmagic_initialize();
}

JNIEXPORT jint JNICALL
Java_com_kodeholic_httpswithopenssl_lib_jni_TLSNativeIF_tls_1open(JNIEnv *env, jobject instance,
                                                 jint type,
                                                 jstring host_,
                                                 jint port,
                                                 jbyteArray cert_,
                                                 jint cert_len,
                                                 jbyteArray ip_,
                                                 jint timeo) {
    const char *host = env->GetStringUTFChars(host_, 0);
    jbyte *cert = env->GetByteArrayElements(cert_, NULL);
    jbyte *ip = env->GetByteArrayElements(ip_, NULL);

    // TODO
    char local_cert[cert_len+1];
    memcpy(local_cert, cert, cert_len);
    local_cert[cert_len] = 0;

    char local_ip[128];
    memset(local_ip, 0x00, sizeof(local_ip));

    LOGD("++++JNI_TLS_OPEN(enter) - type: %d, host: %s, port: %d, cert_len: %d, timeo: %d",
         type, host, port, cert_len, timeo);

    int result = tls_open(type, host, port, local_cert, cert_len, local_ip, sizeof(local_ip), timeo);
    if (result != -1) {
        snprintf((char *)ip, 128, "%s", local_ip);
    }

    env->ReleaseStringUTFChars(host_, host);
    env->ReleaseByteArrayElements(cert_, cert, 0);
    env->ReleaseByteArrayElements(ip_, ip, 0);

    LOGD("++++JNI_TLS_OPEN(leave) - local_ip: %s, result: %d", local_ip, result);

    return result;
}


JNIEXPORT jint JNICALL
Java_com_kodeholic_httpswithopenssl_lib_jni_TLSNativeIF_tls_1close(JNIEnv *env, jobject instance,
                                                  jint tlsconn_id) {

    LOGD("++++JNI_TLS_CLOSE(enter) - TLSCONN_ID(%d)", tlsconn_id);

    // TODO
    int result = tls_close(tlsconn_id);

    LOGD("++++JNI_TLS_CLOSE(leave) - result: %d", result);

    return result;
}

JNIEXPORT jint JNICALL
Java_com_kodeholic_httpswithopenssl_lib_jni_TLSNativeIF_tls_1read(JNIEnv *env, jobject instance,
                                                 jint tlsconn_id,
                                                 jbyteArray bytes_,
                                                 jint off,
                                                 jint len,
                                                 jint timeo) {
    jbyte *bytes = env->GetByteArrayElements(bytes_, NULL);

    LOGD("++++JNI_TLS_READ(enter) - TLSCONN_ID(%d), off: %d, len: %d, timeo: %d", tlsconn_id, off, len, timeo);

    // TODO
    int result = tls_read(tlsconn_id, (unsigned char *)bytes+off, len, timeo);

    env->ReleaseByteArrayElements(bytes_, bytes, 0);

    LOGD("++++JNI_TLS_READ(leave) - result: %d", result);

    return result;
}

JNIEXPORT jint JNICALL
Java_com_kodeholic_httpswithopenssl_lib_jni_TLSNativeIF_tls_1write(JNIEnv *env, jobject instance,
                                                  jint tlsconn_id,
                                                  jbyteArray bytes_,
                                                  jint off,
                                                  jint len,
                                                  jint timeo) {
    jbyte *bytes = env->GetByteArrayElements(bytes_, NULL);

    LOGD("++++JNI_TLS_WRITE(enter) - TLSCONN_ID(%d), off: %d, len: %d, timeo: %d", tlsconn_id, off, len, timeo);

    // TODO
    int result = tls_write(tlsconn_id, (unsigned char *)bytes+off, len, timeo);

    env->ReleaseByteArrayElements(bytes_, bytes, 0);

    LOGD("++++JNI_TLS_WRITE(leave) - result: %d", result);

    return result;
}

JNIEXPORT jint JNICALL
Java_com_kodeholic_httpswithopenssl_lib_jni_TLSNativeIF_tls_1signal(JNIEnv *env, jobject instance,
                                                   jint tlsconn_id,
                                                   jint b) {

    LOGD("++++JNI_TLS_SIGNAL(enter) - TLSCONN_ID(%d)", tlsconn_id);

    // TODO
    int result = tls_signal(tlsconn_id, b);

    LOGD("++++JNI_TLS_SIGNAL(leave) - result: %d", result);

    return result;
}

#ifdef __cplusplus
}
#endif