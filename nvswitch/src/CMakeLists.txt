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
	switch.c
)

include_directories("${CMAKE_SOURCE_DIR}/libnvcore/src/")
target_link_libraries(netvirt-switch
	nvcore
	ssl
	crypto
	pthread
	jansson
	event
	event_openssl
)

install(TARGETS netvirt-switch
	DESTINATION bin)
