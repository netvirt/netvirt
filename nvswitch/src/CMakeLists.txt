set(CMAKE_C_FLAGS "-g -W -Wall -Wno-unused-parameter -DNVSWITCH_VERSION='\"${CPACK_PACKAGE_VERSION}\"' ${compiler_options}")
set(CMAKE_CXX_FLAGS "-g -W -Wall -Wno-unused-parameter -DNVSWITCH_VERSION='\"${CPACK_PACKAGE_VERSION}\"' ${compiler_options}")

add_subdirectory(tests)

add_executable(netvirt-switch
	control.c
	ctable.c
	inet.c
	linkst.c
	main.c
	request.c
	vnetwork.c
	session.c
	switch.c
)

find_library(EVENT_CORE_LIBRARY event_core HINTS /usr/local/lib)
find_library(EVENT_SSL_LIBRARY event_openssl HINTS /usr/local/lib)

include_directories("/usr/local/include")
include_directories("${CMAKE_SOURCE_DIR}/libconfig/lib/")
include_directories("${CMAKE_SOURCE_DIR}/libnvcore/src/")
include_directories("${CMAKE_SOURCE_DIR}/libnvcore/src/protocol/")
link_directories("${CMAKE_SOURCE_DIR}/libconfig/lib/.libs")
target_link_libraries(netvirt-switch
	nvcore
	${EVENT_CORE_LIBRARY}
	${EVENT_SSL_LIBRARY}
	ssl
	crypto
	pthread
	jansson
	${CMAKE_SOURCE_DIR}/libconfig/lib/.libs/libconfig.a
)

install(TARGETS netvirt-switch
	DESTINATION bin)
