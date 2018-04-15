set(CMAKE_C_FLAGS "-I/usr/local/include -L/usr/local/lib -g -W -Wall -Wno-unused-parameter -DNVSWITCH_VERSION='\"${CPACK_PACKAGE_VERSION}\"' ${compiler_options}")

add_subdirectory(tests)

add_executable(netvirt-switch
	control.c
	main.c
	switch.c
)

target_link_libraries(netvirt-switch
	nv
	jansson
	event_core
	event_extra
	event_openssl
)

install(TARGETS netvirt-switch
	DESTINATION bin)
