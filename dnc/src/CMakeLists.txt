set(CMAKE_C_FLAGS "-g -Wall")

set(dnc_sources
	config.c
	dnc.c
	session.c)

if (0)
	find_package(Qt4 REQUIRED)
	set(gui_sources
		gui/main.cpp
		gui/MyWindow.cpp)

	set(gui_headers
		gui/MyWindow.h)

	QT4_WRAP_CPP(gui_headers_moc ${gui_headers})
	QT4_WRAP_UI(gui_form_headers gui/dnc.ui)

	include(${QT_USE_FILE})
	add_definitions(${QT_DEFINITIONS})

	add_executable(dnc ${dnc_sources} ${gui_sources} ${gui_headers_moc} ${gui_form_headers})

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
include_directories("${CMAKE_SOURCE_DIR}/libconfig-1.4.9/lib")

if(WIN32)

	set(TAPCFG_LIBRARIES ${CMAKE_SOURCE_DIR}/tapcfg-1.0.0/build/tapcfg.dll)
	set(LIBCONFIG_LIBRARIES ${CMAKE_SOURCE_DIR}/libconfig-1.4.9/lib/.libs/libconfig-9.dll)

	target_link_libraries(dnc
		${TAPCFG_LIBRARIES}
		${LIBCONFIG_LIBRARIES}
		dnds
	)

else()
	set(TAPCFG_LIBRARIES ${CMAKE_SOURCE_DIR}/tapcfg-1.0.0/build/libtapcfg.a)

	target_link_libraries(dnc
		${TAPCFG_LIBRARIES}
		${LIBCONFIG_LIBRARIES}
		dnds
		config
	)
endif()

target_link_libraries(dnc
	${TAPCFG_LIBRARIES}
	${LIBCONFIG_LIBRARIES}
	dnds
	pthread
)

install(TARGETS dnc
	DESTINATION bin)
