set(CMAKE_C_FLAGS "-g -Wall")

if (WIN32)
	set (win_rc_icon icon.rc)
else()
	set (win_rc_icon "")
endif()

set(dnc_sources
	config.c
	dnc.c
	session.c)

link_directories("${CMAKE_SOURCE_DIR}/libconfig-1.4.9/lib/.libs")
link_directories("${CMAKE_SOURCE_DIR}/tapcfg-1.0.0/build")

if (1)
	find_package(Qt4 REQUIRED)
	set(gui_sources
		gui/main.cpp
		gui/MyWindow.cpp)

	set(gui_headers
		gui/MyWindow.h)

	QT4_ADD_RESOURCES(gui_rccs_srcs "./gui/systray.qrc")
	QT4_WRAP_CPP(gui_headers_moc ${gui_headers})
	QT4_WRAP_UI(gui_form_headers gui/dnc.ui)

	include(${QT_USE_FILE})
	add_definitions(${QT_DEFINITIONS})

	add_executable(dnc ${dnc_sources} ${gui_sources} ${gui_headers_moc} ${gui_form_headers} ${gui_rccs_srcs} ${win_rc_icon})

	if (WIN32)
		set_target_properties(dnc PROPERTIES LINK_FLAGS "-mwindows")
	endif()

	target_link_libraries(dnc ${QT_LIBRARIES})

else()

	set(cli_sources
		cli/main.c)

	add_executable(dnc ${dnc_sources} ${cli_sources})
endif()

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

include_directories("${CMAKE_SOURCE_DIR}/libdnds/src/protocol/")
include_directories("${CMAKE_SOURCE_DIR}/tapcfg-1.0.0/src/include/")
include_directories("${CMAKE_SOURCE_DIR}/libconfig-1.4.9/lib/")

target_link_libraries(dnc
	config
	dnds
	pthread
	tapcfg
)

install(TARGETS dnc
    DESTINATION bin)
if (APPLE)
    install(FILES ${CMAKE_SOURCE_DIR}/libconfig-1.4.9/lib/.libs/libconfig.9.dylib
            DESTINATION lib)
    install(FILES ${CMAKE_SOURCE_DIR}/tapcfg-1.0.0/build/libtapcfg.dylib
            DESTINATION lib)
endif()
