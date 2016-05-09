#include <android/log.h>

#define TAG "ToyVpnService"

#define log_info(...) \
        __android_log_write(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
