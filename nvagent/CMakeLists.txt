cmake_minimum_required(VERSION 2.6)

include_directories("../libnvcore/src/")
include_directories("../libnvcore/protocol/")

add_subdirectory(src)

if (APPLE)
	set(CPACK_GENERATOR "DragNDrop")
else()

	install(FILES ./src/gui/rc/nvagent.svg DESTINATION /usr/share/icons/hicolor/scalable/apps/)
	install(FILES ./xdesktop/nvagent.desktop DESTINATION /usr/share/applications/)

	set(CPACK_GENERATOR "DEB")
	if (WITH_GUI)
	  set(CPACK_PACKAGE_NAME "netvirt-agent-gui")
	else()
	  set(CPACK_PACKAGE_NAME "netvirt-agent-cli")
	endif()
	set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "NetVirt Agent - Connect to your virtual network")
	set(CPACK_DEBIAN_PACKAGE_DEPENDS "libcap2-bin")
	set(CPACK_DEBIAN_PACKAGE_SECTION "net")
	set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Nicolas J. Bouliane <admin@netvirt.org>")
	set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA ${CMAKE_CURRENT_SOURCE_DIR}/postinst; ${CMAKE_CURRENT_SOURCE_DIR}/postrm)
endif()

include(CPack)
