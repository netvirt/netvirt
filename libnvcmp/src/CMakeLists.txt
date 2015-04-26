find_package(PROTOBUF-C)

set(CMAKE_C_FLAGS "-g -W -Wall ${compiler_options}")
set(CMAKE_CXX_FLAGS "-g -W -Wall ${compiler_options}")

add_executable(nvcmp
	nvcm.pb-c.c
	nvcm.pb-c.h
	test.c
)

include_directories(${PROTOBUF_INCLUDE_DIR})

target_link_libraries(nvcmp
	${PROTOBUF_LIBRARIES}
)
