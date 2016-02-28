.PHONY: default apk clean

SRC_DIR=$(pwd)/src
BUILD_DIR=build

default:
	docker run -it --rm -v ${SRC_DIR}:/home/user rabits/qt:5.4-android qmake ANDROID_DEPLOYMENT_SETTINGS_FILE=/home/user/deployment-settings.json
	docker run -it --rm -v ${SRC_DIR}:/home/user rabits/qt:5.4-android make
	docker run -it --rm -v ${SRC_DIR}:/home/user rabits/qt:5.4-android make install INSTALL_ROOT=/home/user/${BUILD_DIR}

apk:
	docker run -it --rm -v ${SRC_DIR}:/home/user rabits/qt:5.4-android androiddeployqt --release --input deployment-settings.json --output /home/user/${BUILD_DIR}

clean:
	docker run -it --rm -v ${SRC_DIR}:/home/user rabits/qt:5.4-android make distclean
	docker run -it --rm -v ${SRC_DIR}:/home/user rabits/qt:5.4-android rm -rf ${BUILD_DIR} deployment-settings.json
