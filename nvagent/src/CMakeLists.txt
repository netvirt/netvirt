set(CMAKE_C_FLAGS "-g -W -Wall -DDNCVERSION='\"${CPACK_PACKAGE_VERSION}\"' ${compiler_options}")
set(CMAKE_CXX_FLAGS "-g -W -Wall -DDNCVERSION='\"${CPACK_PACKAGE_VERSION}\"' ${compiler_options}")
set(CMAKE_INCLUDE_CURRENT_DIR ON)

add_subdirectory(tests)

option (WITH_GUI "WITH_GUI" ON)

if (WIN32)
	set (win_rc_icon icon.rc)
else()
	set (win_rc_icon "")
endif()

set(nvagent_sources
	agent.c
	config.c
	p2p.c
	session.c)

message(STATUS "CMAKE_SOURCE_DIR" ${CMAKE_SOURCE_DIR})

if (WIN32)
	link_directories("${CMAKE_SOURCE_DIR}/libconfig-win32/lib/.libs")
	link_directories("${CMAKE_SOURCE_DIR}/tapcfg-win32/build")
elseif(APPLE)
	link_directories("${CMAKE_SOURCE_DIR}/libconfig-macos/lib/.libs")
	link_directories("${CMAKE_SOURCE_DIR}/tapcfg-macos/build")
elseif(UNIX)
	link_directories("${CMAKE_SOURCE_DIR}/libconfig-linux/lib/.libs")
	link_directories("${CMAKE_SOURCE_DIR}/tapcfg-linux/build")
endif()

if (WITH_GUI)
	add_definitions( -DQT_EDITION=QT_EDITION_OPENSOURCE )
	find_package(Qt4 COMPONENTS QtCore QtGui QtNetwork REQUIRED)
	set(gui_sources
                gui/main.cpp
		gui/maindialog.cpp
		gui/accountsettings.cpp
		gui/logsettings.cpp
		gui/generalsettings.cpp
		gui/wizarddialog.cpp)

	set(gui_headers
		gui/maindialog.h
		gui/accountsettings.h
		gui/logsettings.h
		gui/generalsettings.h
		gui/wizarddialog.h)

	QT4_ADD_RESOURCES(gui_rccs_srcs "./gui/agent.qrc")
	QT4_WRAP_CPP(gui_headers_moc ${gui_headers})
	QT4_WRAP_UI(gui_form_headers
			gui/maindialog.ui
			gui/accountsettings.ui
			gui/logsettings.ui
			gui/generalsettings.ui
			gui/wizarddialog.ui)

	include(${QT_USE_FILE})
	add_definitions(${QT_DEFINITIONS})

	add_executable(nvagent MACOSX_BUNDLE WIN32 ${nvagent_sources} ${gui_sources} ${gui_headers_moc} ${gui_form_headers} ${gui_rccs_srcs} ${win_rc_icon})

	if (WIN32)
		set_target_properties(nvagent PROPERTIES LINK_FLAGS "-mwindows")
	endif()

	target_link_libraries(nvagent ${QT_LIBRARIES})

else()
	set(cli_sources
		cli/main.c)

	add_executable(nvagent ${nvagent_sources} ${cli_sources})
endif()

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

include_directories("${CMAKE_SOURCE_DIR}/libcore/src/protocol/")

if (WIN32)
	include_directories("${CMAKE_SOURCE_DIR}/tapcfg-win32/src/include/")
	include_directories("${CMAKE_SOURCE_DIR}/libconfig-win32/lib/")
elseif (APPLE)
	include_directories("${CMAKE_SOURCE_DIR}/tapcfg-macos/src/include/")
	include_directories("${CMAKE_SOURCE_DIR}/libconfig-macos/lib/")
elseif (UNIX)
	include_directories("${CMAKE_SOURCE_DIR}/tapcfg-linux/src/include/")
	include_directories("${CMAKE_SOURCE_DIR}/libconfig-linux/lib/")
endif()

if (APPLE)
	target_link_libraries(nvagent
		${CMAKE_SOURCE_DIR}/tapcfg-macos/build/libtapcfg.a
		${CMAKE_SOURCE_DIR}/libconfig-macos/lib/.libs/libconfig.a
		dnds
		ssl
		crypto
		pthread
	)
elseif (WIN32)
	target_link_libraries(nvagent
		config
		dnds
		pthread
#		tapcfg
		${CMAKE_SOURCE_DIR}/tapcfg-win32/build/tapcfg.dll
		${OPENSSL_LIBRARIES}
	)
else()
	target_link_libraries(nvagent
		-Wl,-Bstatic
		tapcfg
		config
		dnds
		ssl
		-Wl,-Bdynamic
		crypto
		pthread
	)
endif()

install(TARGETS nvagent
    BUNDLE DESTINATION . COMPONENT Runtime
    RUNTIME DESTINATION bin COMPONENT Runtime
    )

if (APPLE)
    install(CODE "
        file(WRITE \"\${CMAKE_INSTALL_PREFIX}/${qtconf_dest_dir}/qt.conf\" \"\")
        " COMPONENT Runtime)
    install(DIRECTORY ${CMAKE_SOURCE_DIR}/osx/DynVPN-launcher.app DESTINATION . USE_SOURCE_PERMISSIONS COMPONENT Runtime)
    install(DIRECTORY ${CMAKE_SOURCE_DIR}/osx/tuntap_20111101.pkg DESTINATION . USE_SOURCE_PERMISSIONS COMPONENT Runtime)
    set(DIRS ${QT_LIBRARY_DIRS})
    set(APPS "\${CMAKE_INSTALL_PREFIX}/${apple_package}")
    install(CODE "
        file(GLOB_RECURSE QTPLUGINS
          \"\${CMAKE_INSTALL_PREFIX}/${library_dest_dir}/plugins/*${CMAKE_SHARED_LIBRARY_SUFFIX}\")
        set(BU_CHMOD_BUNDLE_ITEMS 1)
        include(BundleUtilities)
        fixup_bundle(\"${APPS}\" \"\${QTPLUGINS}\" \"${DIRS}\")
        " COMPONENT Runtime)
endif ()
