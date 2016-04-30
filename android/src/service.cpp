#include <android/log.h>
#include <jni.h>
#include <QtAndroidExtras/QAndroidJniObject>

#include "service.h"

JNIEXPORT void JNICALL Java_com_netvirt_netvirt_ToyVpnServiceQt_main(JNIEnv *env, jobject thisObj, jobject toyVpnServiceJava_) {
    __android_log_write(ANDROID_LOG_INFO, "ToyVpnService", "beginning of main()");

    QAndroidJniObject toyVpnServiceJava(toyVpnServiceJava_);
    toyVpnServiceJava.callMethod<void>("_run");
    __android_log_write(ANDROID_LOG_INFO, "ToyVpnService", "ending of main()");
}
