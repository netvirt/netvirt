set(CMAKE_C_FLAGS "-I/usr/local/include -L/usr/local/lib -g -W -Wall -DNVAGENT_VERSION='\"${CPACK_PACKAGE_VERSION}\"' ${compiler_options}")
set(CMAKE_INCLUDE_CURRENT_DIR ON)

add_subdirectory(tests)

option (WITH_GUI "WITH_GUI" ON)

if (APPLE)
  if (NOT OPENSSL_ROOT_DIR)
    set(OPENSSL_ROOT_DIR /usr/local/opt/openssl)
  endif()
  include_directories("${OPENSSL_ROOT_DIR}/include")
  link_directories("${OPENSSL_ROOT_DIR}/lib")
endif()

if (NOT TAPCFG_ROOT_DIR)
  set(TAPCFG_ROOT_DIR ${CMAKE_SOURCE_DIR}/tapcfg)
endif()

include_directories("${TAPCFG_ROOT_DIR}/src/include/")

if (WIN32)
	include_directories("${LIBCURL_ROOT_DIR}/include/"  "${LIBRESSL_ROOT_DIR}/include/" "${LIBEVENT_ROOT_DIR}/include/" "${LIBJANSSON_ROOT_DIR}/src/" "${CMAKE_SOURCE_DIR}/libnv/src/")
	set (win_rc_icon gui/rc/icon.rc)
else()
	set (win_rc_icon "")
endif()

set(nvagent_sources
	control.c
	ndb.c
	switch.c)

message(STATUS "CMAKE_SOURCE_DIR" ${CMAKE_SOURCE_DIR})

link_directories("${TAPCFG_ROOT_DIR}/build")

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

	QT4_ADD_RESOURCES(gui_rccs_srcs "./gui/nvagent.qrc")
	QT4_WRAP_CPP(gui_headers_moc ${gui_headers})
	QT4_WRAP_UI(gui_form_headers
			gui/maindialog.ui
			gui/accountsettings.ui
			gui/logsettings.ui
			gui/generalsettings.ui
			gui/wizarddialog.ui)

	include(${QT_USE_FILE})
	add_definitions(${QT_DEFINITIONS})

	add_executable(netvirt-agent2 MACOSX_BUNDLE WIN32 ${nvagent_sources} ${gui_sources} ${gui_headers_moc} ${gui_form_headers} ${gui_rccs_srcs} ${win_rc_icon})

	if (WIN32)
		set_target_properties(netvirt-agent2 PROPERTIES LINK_FLAGS "-mwindows")
	endif()

	target_link_libraries(netvirt-agent2 ${QT_LIBRARIES})

else()
	set(cli_sources
		cli/main.c)

	add_executable(netvirt-agent2 MACOSX_BUNDLE ${nvagent_sources} ${cli_sources})
endif()

if (APPLE)
	target_link_libraries(netvirt-agent2
		${TAPCFG_ROOT_DIR}/build/libtapcfg.a
		curl
		nv
		ssl
		crypto
		jansson
		event_core
		event_extra
		event_openssl
	)
elseif (WIN32)

	file(GLOB LIBS_FOR_WIN32
		${LIBCURL_ROOT_DIR}/lib/.libs/libcurl*dll
		${LIBRESSL_ROOT_DIR}/ssl/.libs/libssl*dll
		${LIBRESSL_ROOT_DIR}/crypto/.libs/libcrypto*dll
		${LIBJANSSON_ROOT_DIR}/src/.libs/libjansson*dll
		${LIBEVENT_ROOT_DIR}/.libs/libevent*dll)

	target_link_libraries(netvirt-agent2
		ws2_32
		nv
		${LIBS_FOR_WIN32}
		${OPENSSL_LIBRARIES}
		${TAPCFG_ROOT_DIR}/build/tapcfg.dll
	)
else()
	target_link_libraries(netvirt-agent2
		curl
		${TAPCFG_ROOT_DIR}/build/libtapcfg.a
		nv
		ssl
		crypto
		event_core
		event_extra
		event_openssl
		jansson
	)
endif()

install(TARGETS netvirt-agent2
    BUNDLE DESTINATION . COMPONENT Runtime
    RUNTIME DESTINATION bin COMPONENT Runtime
    )

if (APPLE)
    set(APPS "\${CMAKE_INSTALL_PREFIX}/${apple_package}")
    install(DIRECTORY ${CMAKE_SOURCE_DIR}/osx/tuntap_20111101.pkg DESTINATION . USE_SOURCE_PERMISSIONS COMPONENT Runtime)
    if (WITH_GUI)
        install(CODE "
            file(WRITE \"\${CMAKE_INSTALL_PREFIX}/${qtconf_dest_dir}/qt.conf\" \"\")
            " COMPONENT Runtime)
        install(DIRECTORY ${CMAKE_SOURCE_DIR}/osx/NetVirt-Agent-launcher.app DESTINATION . USE_SOURCE_PERMISSIONS COMPONENT Runtime)
        set(DIRS ${QT_LIBRARY_DIRS})
        install(CODE "
            file(GLOB_RECURSE QTPLUGINS
              \"\${CMAKE_INSTALL_PREFIX}/${library_dest_dir}/plugins/*${CMAKE_SHARED_LIBRARY_SUFFIX}\")
            set(BU_CHMOD_BUNDLE_ITEMS 1)
            include(BundleUtilities)
            fixup_bundle(\"${APPS}\" \"\${QTPLUGINS}\" \"${DIRS}\")
            " COMPONENT Runtime)
    endif()
endif ()
