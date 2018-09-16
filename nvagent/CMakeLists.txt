cmake_minimum_required(VERSION 2.6)

include_directories("../libnv/src/")

add_subdirectory(src)

if (APPLE)
	set(CPACK_GENERATOR "DragNDrop")
else()
	set(CPACK_GENERATOR "DEB")
	if (WITH_GUI)
		install(FILES ./src/gui/rc/nvagent.svg DESTINATION /usr/share/icons/hicolor/scalable/apps/)
		install(FILES ./xdesktop/nvagent.desktop DESTINATION /usr/share/applications/)
	endif()
	set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "NetVirt Agent - Connect to your virtual network")
	set(CPACK_DEBIAN_PACKAGE_DEPENDS "libcap2-bin")
	set(CPACK_DEBIAN_PACKAGE_SECTION "net")
	set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Nicolas J. Bouliane <nib@dynvpn.com>")
	set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA ${CMAKE_CURRENT_SOURCE_DIR}/postinst; ${CMAKE_CURRENT_SOURCE_DIR}/postrm)
endif()

if (WITH_GUI)
	set(CPACK_PACKAGE_NAME "netvirt-agent2-gui")
else()
	set(CPACK_PACKAGE_NAME "netvirt-agent2-cli")
endif()

include(CPack)
