.PHONY: default apk clean

PWD=$(shell pwd)
BUILD_DIR=build
KEYSTORE=${PWD}/netvirt.keystore
KEYSTORE_ALIAS=netvirt
SRC_DIR=${PWD}/src
KEYSTORE_PASSWORD=netvirt

APK_SIGNED=${SRC_DIR}/${BUILD_DIR}/bin/QtApp-release-signed.apk
APK_UNSIGNED=${SRC_DIR}/${BUILD_DIR}/bin/QtApp-release-unsigned.apk

default:
	docker run -it --rm -v ${SRC_DIR}:/home/user rabits/qt:5.4-android qmake ANDROID_DEPLOYMENT_SETTINGS_FILE=/home/user/deployment-settings.json
	docker run -it --rm -v ${SRC_DIR}:/home/user rabits/qt:5.4-android make
	docker run -it --rm -v ${SRC_DIR}:/home/user rabits/qt:5.4-android make install INSTALL_ROOT=/home/user/${BUILD_DIR}

apk:
	docker run -it --rm -v ${SRC_DIR}:/home/user rabits/qt:5.4-android androiddeployqt --release --input deployment-settings.json --output /home/user/${BUILD_DIR}

genkey:
	keytool -genkey -v -keystore ${KEYSTORE} -alias ${KEYSTORE_ALIAS} -keyalg RSA -keysize 2048 -validity 10000

sign: ${KEYSTORE} ${APK_UNSIGNED}
	jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore ${KEYSTORE} -storepass ${KEYSTORE_PASSWORD} ${SRC_DIR}/${BUILD_DIR}/bin/QtApp-release-unsigned.apk ${KEYSTORE_ALIAS}
	mv ${APK_UNSIGNED} ${APK_SIGNED}

install: ${APK_SIGNED}
	adb install -r ${APK_SIGNED}

clean:
	docker run -it --rm -v ${SRC_DIR}:/home/user rabits/qt:5.4-android make distclean
	rm -rf ${SRC_DIR}/${BUILD_DIR} deployment-settings.json
