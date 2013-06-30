; Binaries

; dnc.conf
; dnc.exe

# /!\ You need to edit that section
!define MINGW_PATH /usr/lib/gcc/i686-w64-mingw32/4.6/
!define PTHREAD_PATH /usr/x86_64-w64-mingw32/lib
!define OPENSSL_PATH /opt/mingw32/mingw32/bin
!define QT_PATH /media/nib/Windows7_OS/Qt/4.8.4/bin

SetCompressor /FINAL /SOLID lzma
Name "DNDS Client"
OutFile "dnds-client_x86.exe"

; Ask admin privileges
RequestExecutionLevel admin
ShowInstDetails show
ShowUninstDetails show

; == License page ==

;!insertmacro MUI_PAGE_LICENSE LICENSE


; == Install directory page ==
InstallDir $PROGRAMFILES\dnds-client
section

setOutPath $INSTDIR
File dnc/src/dnc.exe
File dnc/dnc.conf
File libdnds/src/libdnds.dll
File udt4/src/libudt.dll
File libconfig-1.4.9/lib/.libs/libconfig-9.dll
File tapcfg-1.0.0/build/tapcfg.dll
File ${MINGW_PATH}/libgcc_s_sjlj-1.dll
File ${MINGW_PATH}/libstdc++-6.dll
File ${PTHREAD_PATH}/pthreadGC2.dll
File ${OPENSSL_PATH}/libeay32.dll
File ${OPENSSL_PATH}/ssleay32.dll
File ${QT_PATH}/libgcc_s_dw2-1.dll
File ${QT_PATH}/mingwm10.dll
File ${QT_PATH}/QtCore4.dll
File ${QT_PATH}/QtGui4.dll

sectionEnd
