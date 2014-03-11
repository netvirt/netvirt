cmake_minimum_required(VERSION 2.6)

include_directories("../libdnds/src/")
include_directories("../libdnds/protocol/")

add_subdirectory(src)

if (APPLE)
	set(CPACK_GENERATOR "DragNDrop")
else()

	install(FILES ./src/gui/rc/dnc.svg DESTINATION /usr/share/icons/hicolor/scalable/apps/)
	install(FILES ./xdesktop/dnc.desktop DESTINATION /usr/share/applications/)

	set(CPACK_GENERATOR "DEB")
	if (WITH_GUI)
	  set(CPACK_PACKAGE_NAME "dynvpn-client-gui")
	else()
	  set(CPACK_PACKAGE_NAME "dynvpn-client-cli")
	endif()
	set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "DynVPN Client - DNDS is a Dynamic VPN solution that allow you to securely access and manage computers/devices via Internet")
	set(CPACK_DEBIAN_PACKAGE_SECTION "net")
	set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Nicolas J. Bouliane <nib@dynvpn.com>")
	set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA ${CMAKE_CURRENT_SOURCE_DIR}/postinst)
endif()

include(CPack)
