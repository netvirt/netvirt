!ifndef MINGW_PATH
	!define MINGW_PATH /usr/lib/gcc/i686-w64-mingw32/4.6/
!endif
!ifndef PTHREAD_PATH
	!define PTHREAD_PATH /usr/i686-w64-mingw32/lib/
!endif
!ifndef OPENSSL_PATH
	!define OPENSSL_PATH /opt/mingw32/mingw32/bin
!endif
!ifndef QT_PATH
	!define QT_PATH /media/nib/Windows7_OS/Qt/4.8.4/bin
!endif

# Define the path of the build directory
!ifndef BDIR
	!define BDIR "build.w32"
!endif

SetCompressor /FINAL /SOLID lzma

;-------------------
; Include Modern UI
	!include "MUI2.nsh"

	!define MUI_ICON "./dnc/src/gui/rc/dnc.ico"
	!define MUI_UNICON "./dnc/src/gui/rc/dnc.ico"

	!define MUI_HEADERIMAGE
	!define MUI_HEADERIMAGE_RIGH
	!define MUI_HEADERIMAGE_BITMAP "./graphics/Header/orange-r.bmp"
	!define MUI_HEADERIMAGE_UNBITMAP "./graphics/Header/orange-uninstall-r.bmp"

	!define MUI_WELCOMEFINISHPAGE_BITMAP "./graphics/Wizard/orange.bmp"
	!define MUI_UNWELCOMEFINISHPAGE_BITMAP "./graphics/Wizard/orange-uninstall.bmp"

; --------
; General
	!include "x64.nsh"
	!define /date NOW "%y.%m.%d"
	Name "DynVPN Client"
	OutFile "${BDIR}/dynvpn-client-${NOW}_x86.exe"
	InstallDir $PROGRAMFILES\dynvpn-client

	; Ask admin privileges
	RequestExecutionLevel admin
	ShowInstDetails show
	ShowUninstDetails show

;-------
; Pages
	; Install
	!insertmacro MUI_PAGE_WELCOME
	!insertmacro MUI_PAGE_COMPONENTS
	!insertmacro MUI_PAGE_DIRECTORY

	; Start Menu Folder Page Configuration
	Var StartMenuFolder
	!define MUI_STARTMENUPAGE_REGISTRY_ROOT "HKCU"
	!define MUI_STARTMENUPAGE_REGISTRY_KEY "Software\dnc"
	!define MUI_STARTMENUPAGE_REGISTRY_VALUENAME "Start Menu Folder"
	!insertmacro MUI_PAGE_STARTMENU Application $StartMenuFolder

	!insertmacro MUI_PAGE_INSTFILES

	; Uninstall
	!insertmacro MUI_UNPAGE_CONFIRM
	!insertmacro MUI_UNPAGE_INSTFILES

;-----------
; Languages
	!insertmacro MUI_LANGUAGE "English"

;-------------------
; Installer section
	Section "DynVPN client" dncExe
		setOutPath $INSTDIR

		File ${BDIR}/dnc/src/dnc.exe
		File udt4/src/libudt.dll
		File libconfig-win32/lib/.libs/libconfig-9.dll
		File tapcfg-win32/build/tapcfg.dll
		File ${MINGW_PATH}/libgcc_s_sjlj-1.dll
		File ${MINGW_PATH}/libstdc++-6.dll
		File ${MINGW_PATH}/libwinpthread-1.dll	
		File ${PTHREAD_PATH}/pthreadGC2.dll
		File ${OPENSSL_PATH}/libeay32.dll
		File ${OPENSSL_PATH}/ssleay32.dll
		File ${QT_PATH}/libgcc_s_dw2-1.dll
		File ${QT_PATH}/mingwm10.dll
		File ${QT_PATH}/QtCore4.dll
		File ${QT_PATH}/QtGui4.dll
		File ${QT_PATH}/QtNetwork4.dll

		; Create uninstaller
		WriteUninstaller "$INSTDIR\dnc-uninstall.exe"

		!insertmacro MUI_STARTMENU_WRITE_BEGIN Application
			CreateDirectory "$SMPROGRAMS\$StartMenuFolder"
			CreateShortCut	"$DESKTOP\dynvpn-client.lnk" "$INSTDIR\dnc.exe"
			CreateShortCut  "$SMPROGRAMS\$StartMenuFolder\dynvpn-client.lnk" "$INSTDIR\dnc.exe"
			CreateShortCut  "$SMPROGRAMS\$StartMenuFolder\dynvpn-client-uninstall.lnk" "$INSTDIR\dnc-uninstall.exe"
		!insertmacro MUI_STARTMENU_WRITE_END
	sectionEnd

	Section "TAP Virtual Ethernet Adapter" SecTAP
		SetOverwrite on
		setOutPath "$TEMP\"

		File /r tap-driver-32_64/
		DetailPrint "TAP INSTALL (May need confirmation)"

		${If} ${RunningX64}
			setOutPath "$TEMP\tap64\"
			nsExec::ExecToLog '"deltapall.bat" /S /SELECT_UTILITIES=1'
			nsExec::ExecToLog '"addtap.bat" /S /SELECT_UTILITIES=1'
		${Else}
			setOutPath "$TEMP\tap32\"
			nsExec::ExecToLog '"deltapall.bat" /S /SELECT_UTILITIES=1'
			nsExec::ExecToLog '"addtap.bat" /S /SELECT_UTILITIES=1'
		${EndIf}

	sectionEnd

;---------------------
; Uninstaller section
	Section "Uninstall"
		Delete "$INSTDIR\*"
		RMDir "$INSTDIR"

		!insertmacro MUI_STARTMENU_GETFOLDER Application $StartMenuFolder
		Delete "$DESKTOP\dynvpn-client.lnk"
		Delete "$SMPROGRAMS\$StartMenuFolder\dynvpn-client.lnk"
		Delete "$SMPROGRAMS\$StartMenuFolder\dynvpn-client-uninstall.lnk"
		RMDir "$SMPROGRAMS\$StartMenuFolder"

		StrCpy $2 $INSTDIR "" 3
		Delete "$LOCALAPPDATA\VirtualStore\$2\*"
		RMDir "$LOCALAPPDATA\VirtualStore\$2"

		DeleteRegKey /ifempty HKCU "Software\dnc"
	SectionEnd


