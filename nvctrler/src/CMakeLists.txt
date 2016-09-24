if (PostgreSQL_TYPE_INCLUDE_DIR)
else (PostgreSQL_TYPE_INCLUDE_DIR)
	set (PostgreSQL_TYPE_INCLUDE_DIR ${PostgreSQL_INCLUDE_DIR})
endif (PostgreSQL_TYPE_INCLUDE_DIR)

set(CMAKE_C_FLAGS "-g -W -Wall -Wno-unused-parameter -DNVCTRLER_VERSION='\"${CPACK_PACKAGE_VERSION}\"' ${compiler_options}")
set(CMAKE_CXX_FLAGS "-g -W -Wall -Wno-unused-parameter -DNVCTRLER_VERSION='\"${CPACK_PACKAGE_VERSION}\"' ${compiler_options}")

add_subdirectory(tests)

add_executable(netvirt-ctrler
	ctrler.c
	dao.c
	ippool.c
	main.c
	pki.c
	request.c
)

find_library(EVENT_CORE_LIBRARY event_core HINTS /usr/local/lib)
find_library(EVENT_SSL_LIBRARY event_openssl HINTS /usr/local/lib)

include_directories("/usr/local/include")
include_directories("${CMAKE_SOURCE_DIR}/libconfig/lib/")
include_directories("${CMAKE_SOURCE_DIR}/libnvcore/src/protocol/")
link_directories("${CMAKE_SOURCE_DIR}/libconfig/lib/.libs")
target_link_libraries(netvirt-ctrler
	nvcore
	${EVENT_CORE_LIBRARY}
	${EVENT_SSL_LIBRARY}
	ssl
	ossp-uuid
	pq
	crypto
	jansson
	pthread
	${CMAKE_SOURCE_DIR}/libconfig/lib/.libs/libconfig.a
)

install(TARGETS netvirt-ctrler
	DESTINATION bin)

