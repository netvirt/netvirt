if (PostgreSQL_TYPE_INCLUDE_DIR)
else (PostgreSQL_TYPE_INCLUDE_DIR)
	set (PostgreSQL_TYPE_INCLUDE_DIR ${PostgreSQL_INCLUDE_DIR})
endif (PostgreSQL_TYPE_INCLUDE_DIR)

set(CMAKE_C_FLAGS "-g -W -Wall -DDSDVERSION='\"${CPACK_PACKAGE_VERSION}\"' ${compiler_options}")
set(CMAKE_CXX_FLAGS "-g -W -Wall -DDSDVERSION='\"${CPACK_PACKAGE_VERSION}\"' ${compiler_options}")

add_subdirectory(tests)

add_executable(dsd
	dao.c
	dsd.c
	ippool.c
	main.c
	pki.c
	request.c
)

link_directories("${CMAKE_SOURCE_DIR}/libconfig-linux/lib/.libs")
include_directories("${CMAKE_SOURCE_DIR}/libconfig-linux/lib/")

include_directories("${CMAKE_SOURCE_DIR}/libdnds/src/protocol/")
target_link_libraries(dsd
	${CMAKE_SOURCE_DIR}/libconfig-linux/lib/.libs/libconfig.a
	dnds
	ssl
	ossp-uuid
	pq
	crypto
	pthread
)

install(TARGETS dsd
	DESTINATION bin)

