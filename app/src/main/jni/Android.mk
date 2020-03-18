LOCAL_PATH := $(call my-dir)
BASE_PATH := $(LOCAL_PATH)

#$(warning @echo $(BASE_PATH))

##########################################################
#[2-1]
include $(CLEAR_VARS)
LOCAL_MODULE := crypto-prebuilt
LOCAL_SRC_FILES := $(LOCAL_PATH)/openssl/$(TARGET_ARCH_ABI)/libcrypto.a
include $(PREBUILT_STATIC_LIBRARY)

#[2-2]
include $(CLEAR_VARS)
LOCAL_MODULE := ssl-prebuilt
LOCAL_SRC_FILES := $(LOCAL_PATH)/openssl/$(TARGET_ARCH_ABI)/libssl.a
include $(PREBUILT_STATIC_LIBRARY)

#[2-3] ti2tls_jni
include $(CLEAR_VARS)
LOCAL_MODULE := ti2tls_jni
LOCAL_C_INCLUDES := $(BASE_PATH) $(BASE_PATH)/openssl/h
LOCAL_SRC_FILES := ti2tls_jni.cpp
LOCAL_LDFLAGS := -llog
LOCAL_STATIC_LIBRARIES := \
ssl-prebuilt \
crypto-prebuilt
LOCAL_LDLIBS += -ldl
include $(BUILD_SHARED_LIBRARY)

