if (PostgreSQL_TYPE_INCLUDE_DIR)
else (PostgreSQL_TYPE_INCLUDE_DIR)
	set (PostgreSQL_TYPE_INCLUDE_DIR ${PostgreSQL_INCLUDE_DIR})
endif (PostgreSQL_TYPE_INCLUDE_DIR)

set(CMAKE_C_FLAGS "-I/usr/local/include -L/usr/local/lib -g -W -Wall -Wno-unused-parameter -DNVCTRLER_VERSION='\"${CPACK_PACKAGE_VERSION}\"' ${compiler_options}")

add_subdirectory(tests)

add_executable(netvirt-controller
	agent_control.c
	dao.c
	ippool.c
	main.c
	request.c
	restapi.c
	switch_control.c
)

target_link_libraries(netvirt-controller
	ssl
	crypto
	nv
	pq
	jansson
	event_core
	event_extra
	event_openssl
)

install(TARGETS netvirt-controller
	DESTINATION bin)

