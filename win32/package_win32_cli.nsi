!ifndef MINGW_PATH
	!define MINGW_PATH /usr/lib/gcc/i686-w64-mingw32/4.6
!endif
!ifndef PTHREAD_PATH
	!define PTHREAD_PATH /usr/i686-w64-mingw32/lib
!endif
!ifndef LibreSSL_PATH
	!define LibreSSL_PATH /opt/mingw32/mingw32/bin
!endif

# Define the path of the build directory
!ifndef BDIR
	!define BDIR "build.w32"
!endif

SetCompressor /FINAL /SOLID lzma

;-------------------
; Include Modern UI
	!include "MUI2.nsh"

	!define MUI_ICON "../nvagent/src/gui/rc/nvagent.ico"
	!define MUI_UNICON "../nvagent/src/gui/rc/nvagent.ico"

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
	Name "NetVirt Agent CLI"
	OutFile "${BDIR}/netvirt-agent-cli-${NOW}_x86.exe"
	InstallDir $PROGRAMFILES\netvirt-agent-cli

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

	!insertmacro MUI_PAGE_INSTFILES

	; Uninstall
	!insertmacro MUI_UNPAGE_CONFIRM
	!insertmacro MUI_UNPAGE_INSTFILES

;-----------
; Languages
	!insertmacro MUI_LANGUAGE "English"

;-------------------
; Installer section
	Section "NetVirt Agent CLI"
		setOutPath $INSTDIR

		File ${BDIR}/nvagent/src/netvirt-agent.exe
		File ${UDT4_PATH}/src/libudt.dll
		File ${LIBCONFIG_PATH}/lib/.libs/libconfig-9.dll
		File ${TAPCFG_PATH}/build/tapcfg.dll
		File ${MINGW_PATH}/libgcc_s_sjlj-1.dll
		File ${MINGW_PATH}/libstdc++-6.dll
		File ${MINGW_PATH}/libssp-0.dll
		File ${PTHREAD_PATH}/pthreadGC2.dll
		File ${LibreSSL_PATH}/libcrypto-*.dll
		File ${LibreSSL_PATH}/libssl-*.dll

		CreateDirectory $APPDATA\netvirt\default

		; Create uninstaller
		WriteUninstaller "$INSTDIR\netvirt-agent-uninstall.exe"

	sectionEnd

	Section "TAP Virtual Ethernet Adapter" SecTAP
		SetOverwrite on
		setOutPath "$TEMP\"

		File /r tap-driver-32_64/
		DetailPrint "TAP INSTALL (May need confirmation)"

		${If} ${RunningX64}
			setOutPath "$TEMP\64-bit\"
			nsExec::ExecToLog '"deltapall.bat" /S /SELECT_UTILITIES=1'
			nsExec::ExecToLog '"addtap.bat" /S /SELECT_UTILITIES=1'
		${Else}
			setOutPath "$TEMP\32-bit\"
			nsExec::ExecToLog '"deltapall.bat" /S /SELECT_UTILITIES=1'
			nsExec::ExecToLog '"addtap.bat" /S /SELECT_UTILITIES=1'
		${EndIf}

	sectionEnd

;---------------------
; Uninstaller section
	Section "Uninstall"
		Delete "$INSTDIR\*"
		RMDir "$INSTDIR"

		StrCpy $2 $INSTDIR "" 3
		Delete "$LOCALAPPDATA\VirtualStore\$2\*"
		RMDir "$LOCALAPPDATA\VirtualStore\$2"

	SectionEnd
