if (PostgreSQL_TYPE_INCLUDE_DIR)
else (PostgreSQL_TYPE_INCLUDE_DIR)
	set (PostgreSQL_TYPE_INCLUDE_DIR ${PostgreSQL_INCLUDE_DIR})
endif (PostgreSQL_TYPE_INCLUDE_DIR)

set(CMAKE_C_FLAGS "-g -W -Wall -DDSDVERSION='\"${CPACK_PACKAGE_VERSION}\"' ${compiler_options}")
set(CMAKE_CXX_FLAGS "-g -W -Wall -DDSDVERSION='\"${CPACK_PACKAGE_VERSION}\"' ${compiler_options}")

add_subdirectory(tests)

add_executable(nvctrler
	ctrler.c
	dao.c
	ippool.c
	main.c
	pki.c
	request.c
)

link_directories("${CMAKE_SOURCE_DIR}/libconfig/lib/.libs")
include_directories("${CMAKE_SOURCE_DIR}/libconfig/lib/")

include_directories("${CMAKE_SOURCE_DIR}/libnvcore/src/protocol/")
target_link_libraries(nvctrler
	${CMAKE_SOURCE_DIR}/libconfig/lib/.libs/libconfig.a
	nvcore
	ssl
	ossp-uuid
	pq
	crypto
	pthread
)

install(TARGETS nvctrler
	DESTINATION bin)

