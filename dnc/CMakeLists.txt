cmake_minimum_required(VERSION 2.6)

include_directories("../libdnds/src/")
include_directories("../libdnds/protocol/")

add_subdirectory(src)

if (APPLE)
	install(FILES dnc.conf DESTINATION ${library_dest_dir})
	set(CPACK_GENERATOR "DragNDrop")
else()
	install(FILES dnc.conf DESTINATION /etc/dnds/)

	set(CPACK_GENERATOR "DEB")
	set(CPACK_PACKAGE_NAME "dynvpn-client")
	set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "DynVPN Client - DNDS is a Dynamic VPN solution that allow you to securely access and manage computers/devices via Internet")
	set(CPACK_DEBIAN_PACKAGE_SECTION "net")
	set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Nicolas J. Bouliane <nib@dynvpn.com>")
	endif()

	include(CPack)
