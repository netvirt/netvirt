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
	!define QT_PATH /media/nib/Windows7_OS/Qt/4.8.4
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
	Name "NetVirt Agent"
	OutFile "${BDIR}/netvirt-agent-${NOW}_x86.exe"
	InstallDir $PROGRAMFILES\netvirt-agent

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
	!define MUI_STARTMENUPAGE_REGISTRY_KEY "Software\netvirt-agent"
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
	Section "NetVirt Agent"
		setOutPath $INSTDIR

		File ${BDIR}/nvagent/src/netvirt-agent.exe
		File ${UDT4_PATH}/src/libudt.dll
		File ${LIBCONFIG_PATH}/lib/.libs/libconfig-9.dll
		File ${TAPCFG_PATH}/build/tapcfg.dll
		File ${MINGW_PATH}/libgcc_s_sjlj-1.dll
		File ${MINGW_PATH}/libstdc++-6.dll
		File ${MINGW_PATH}/libssp-0.dll
		File /usr/i686-w64-mingw32/lib/libwinpthread-1.dll
		File ${PTHREAD_PATH}/pthreadGC2.dll
		File ${OPENSSL_PATH}/libeay32.dll
		File ${OPENSSL_PATH}/ssleay32.dll
		File ${QT_PATH}/bin/libgcc_s_dw2-1.dll
		File ${QT_PATH}/bin/mingwm10.dll
		File ${QT_PATH}/bin/QtCore4.dll
		File ${QT_PATH}/bin/QtGui4.dll
		File ${QT_PATH}/bin/QtNetwork4.dll

		CreateDirectory $INSTDIR\imageformats
		setOutPath $INSTDIR\imageformats
		File ${QT_PATH}/plugins/imageformats/qgif4.dll
		File ${QT_PATH}/plugins/imageformats/qico4.dll

		CreateDirectory $APPDATA\netvirt

		; Create uninstaller
		WriteUninstaller "$INSTDIR\netvirt-agent-uninstall.exe"

		!insertmacro MUI_STARTMENU_WRITE_BEGIN Application
			CreateDirectory "$SMPROGRAMS\$StartMenuFolder"
			CreateShortCut  "$DESKTOP\netvirt-agent.lnk" "$INSTDIR\netvirt-agent.exe"
			CreateShortCut  "$SMPROGRAMS\$StartMenuFolder\netvirt-agent.lnk" "$INSTDIR\netvirt-agent.exe"
			CreateShortCut  "$SMPROGRAMS\$StartMenuFolder\netvirt-agent-uninstall.lnk" "$INSTDIR\netvirt-agent-uninstall.exe"
		!insertmacro MUI_STARTMENU_WRITE_END

		; Update icons cache
		System::Call 'Shell32::SHChangeNotify(i 0x8000000, i 0, i 0, i 0)'

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
		Delete "$INSTDIR\imageformats\*"
		RMDir "$INSTDIR\imageformats"

		Delete "$INSTDIR\*"
		RMDir "$INSTDIR"

		Delete "$APPDATA\netvirt\*"
		RMDir "$APPDATA\netvirt"

		!insertmacro MUI_STARTMENU_GETFOLDER Application $StartMenuFolder
		Delete "$DESKTOP\netvirt-agent.lnk"
		Delete "$SMPROGRAMS\$StartMenuFolder\netvirt-agent.lnk"
		Delete "$SMPROGRAMS\$StartMenuFolder\netvirt-agent-uninstall.lnk"
		RMDir "$SMPROGRAMS\$StartMenuFolder"

		StrCpy $2 $INSTDIR "" 3
		Delete "$LOCALAPPDATA\VirtualStore\$2\*"
		RMDir "$LOCALAPPDATA\VirtualStore\$2"

		DeleteRegKey /ifempty HKCU "Software\netvirt-agent"
	SectionEnd
