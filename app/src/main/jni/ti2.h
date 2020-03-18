#ifndef __TI2_COMMON_H__
#define __TI2_COMMON_H__

#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <errno.h>
#include <jni.h>
#include <android/log.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_NOTICE_MEMBER_NUM  200
#define MAX_CHAT_MEMBER_NUM    200
#define MAX_KEY_LEN            32
#define MAX_SEGMENT_SIZE      (15 * 1024)

#define MIN(a, b) (a < b ? a : b)

static int __LOG_DEBUG__ = 1;
static int __NO_LOG() { return 0; }
#define  LOGV(...)  (__LOG_DEBUG__ ? __android_log_print(ANDROID_LOG_VERBOSE, TAG, __VA_ARGS__) : __NO_LOG())
#define  LOGD(...)  (__LOG_DEBUG__ ? __android_log_print(ANDROID_LOG_DEBUG,   TAG, __VA_ARGS__) : __NO_LOG())
#define  LOGI(...)  (__LOG_DEBUG__ ? __android_log_print(ANDROID_LOG_INFO,    TAG, __VA_ARGS__) : __NO_LOG())
#define  LOGW(...)  (__LOG_DEBUG__ ? __android_log_print(ANDROID_LOG_WARN,    TAG, __VA_ARGS__) : __NO_LOG())
#define  LOGE(...)  __android_log_print(ANDROID_LOG_ERROR,   TAG, __VA_ARGS__)

static int common_mutex_init(pthread_mutex_t *p_mutex) {
    pthread_mutexattr_t	attr;

    if (pthread_mutexattr_init(&attr) != 0) {
        return -1;
    }

    if (pthread_mutex_init(p_mutex, &attr) != 0) {
        pthread_mutexattr_destroy(&attr);
        return -1;
    }

    pthread_mutexattr_destroy(&attr);
    return 0;
}

#define MAX_HEX_LEN 128
static char sHex[MAX_HEX_LEN + 1];
static char *byte2hex(char *b, int blen) {
    int n = 0;
    memset(sHex, 0x00, sizeof(sHex));
    for (int i = 0; i < blen && n < MAX_HEX_LEN; i++) {
        n += snprintf(sHex + n, MAX_HEX_LEN - n, "%02x", b[i]);
    }

    return sHex;
}

static char sHexDebug[MAX_HEX_LEN + 1];
static char *byte2debug(char *b, int blen) {
    int n = 0;
    memset(sHexDebug, 0x00, sizeof(sHexDebug));
    for (int i = 0; i < blen && n < MAX_HEX_LEN; i++) {
        if (i == 0) {
            n += snprintf(sHexDebug + n, MAX_HEX_LEN - n, "%02x", b[i]);
        }
        else {
            n += snprintf(sHexDebug + n, MAX_HEX_LEN - n, " %02x", b[i]);
        }
    }

    return sHexDebug;
}

static double __ELAPSED__(struct timeval *p_prev) {
    struct timeval  curr;
    struct timezone timez;
    double elapsed;

    gettimeofday(&curr, &timez);
    elapsed = (curr.tv_sec - p_prev->tv_sec)
              + (double) (curr.tv_usec - p_prev->tv_usec) * 1e-6; /* / 1000000.0; */

    p_prev->tv_sec  = curr.tv_sec;
    p_prev->tv_usec = curr.tv_usec;

    return (elapsed);
}

#ifdef __cplusplus
};
#endif

#endif