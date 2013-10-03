cmake_minimum_required(VERSION 2.6)

include_directories("../libdnds/src/")
include_directories("../libdnds/protocol/")

add_subdirectory(src)

if (APPLE)
install(FILES dnc.conf
        DESTINATION ${library_dest_dir})
set(CPACK_GENERATOR "DragNDrop")
else()
install(FILES dnc.conf
        DESTINATION share/dnds/)

set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Nicolas J. Bouliane <nib@dynvpn.com>")
set(CPACK_GENERATOR "DEB")
endif()

include(CPack)
