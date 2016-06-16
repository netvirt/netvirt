.PHONY: default apk clean

PWD=$(shell pwd)
ROOT=${PWD}
BUILD_DIR=build-android
BUILD_DESKTOP_DIR=build-desktop
KEYSTORE=${ROOT}/netvirt.keystore
KEYSTORE_ALIAS=netvirt
SRC_DIR=${ROOT}/src
KEYSTORE_PASSWORD=netvirt

APK_SIGNED=${BUILD_DIR}/bin/QtApp-release-signed.apk
APK_UNSIGNED=${BUILD_DIR}/bin/QtApp-release-unsigned.apk

default:
	docker run -it --rm -v ${ROOT}:/home/user rabits/qt:5.4-android qmake ANDROID_DEPLOYMENT_SETTINGS_FILE=/home/user/${BUILD_DIR}/deployment-settings.json android.pro -o /home/user/${BUILD_DIR}/Makefile
	docker run -it --rm -v ${ROOT}:/home/user rabits/qt:5.4-android make -C /home/user/${BUILD_DIR}
	docker run -it --rm -v ${ROOT}:/home/user rabits/qt:5.4-android make -C /home/user/${BUILD_DIR} install INSTALL_ROOT=/home/user/${BUILD_DIR}

apk:
	docker run -it --rm -v ${ROOT}:/home/user rabits/qt:5.4-android androiddeployqt --release --input /home/user/${BUILD_DIR}/deployment-settings.json --output /home/user/${BUILD_DIR}

genkey:
	keytool -genkey -v -keystore ${KEYSTORE} -alias ${KEYSTORE_ALIAS} -keyalg RSA -keysize 2048 -validity 10000

sign: ${KEYSTORE} ${APK_UNSIGNED}
	jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore ${KEYSTORE} -storepass ${KEYSTORE_PASSWORD} ${BUILD_DIR}/bin/QtApp-release-unsigned.apk ${KEYSTORE_ALIAS}
	mv ${APK_UNSIGNED} ${APK_SIGNED}

install: ${APK_SIGNED}
	adb install -r ${APK_SIGNED}

clean:
	docker run -it --rm -v ${ROOT}:/home/user rabits/qt:5.4-android make -C /home/user/${BUILD_DIR} distclean
	rm -rf ${BUILD_DIR}

desktop:
	qmake desktop.pro -o ${BUILD_DESKTOP_DIR}/Makefile
	$(MAKE) -C ${BUILD_DESKTOP_DIR}

desktop-cli:
	qmake desktop-cli.pro -o ${BUILD_DESKTOP_DIR}-cli/Makefile
	$(MAKE) -C ${BUILD_DESKTOP_DIR}-cli
