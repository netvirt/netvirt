set(CMAKE_C_FLAGS "-g -W -Wall -DDNDVERSION='\"${CPACK_PACKAGE_VERSION}\"' ${compiler_options}")
set(CMAKE_CXX_FLAGS "-g -W -Wall -DDNDVERSION='\"${CPACK_PACKAGE_VERSION}\"' ${compiler_options}")

add_subdirectory(tests)

add_executable(nvswitch
	context.c
	control.c
	ctable.c
	inet.c
	linkst.c
	main.c
	request.c
	session.c
	switch.c
)
link_directories("${CMAKE_SOURCE_DIR}/libconfig/lib/.libs")
include_directories("${CMAKE_SOURCE_DIR}/libconfig/lib/")

include_directories("${CMAKE_SOURCE_DIR}/libnvcore/src/")
include_directories("${CMAKE_SOURCE_DIR}/libnvcore/src/protocol/")
target_link_libraries(nvswitch
	${CMAKE_SOURCE_DIR}/libconfig/lib/.libs/libconfig.a
	nvcore
	ssl
	crypto
	pthread
)

install(TARGETS nvswitch
	DESTINATION bin)
