if (PostgreSQL_TYPE_INCLUDE_DIR)
else (PostgreSQL_TYPE_INCLUDE_DIR)
	set (PostgreSQL_TYPE_INCLUDE_DIR ${PostgreSQL_INCLUDE_DIR})
endif (PostgreSQL_TYPE_INCLUDE_DIR)

#find_package(PostgreSQL REQUIRED)

set(CMAKE_C_FLAGS "-g")
add_executable(dsd
	dao.c
	dsd.c
	ippool.c
	main.c
	pki.c
	request.c
)

include_directories("${CMAKE_SOURCE_DIR}/../libdnds/src/protocol/")
target_link_libraries(dsd
	${CMAKE_SOURCE_DIR}/../libdnds/src/libdnds.so
	#${PostgreSQL_LIBRARIES}
	pq
	ossp-uuid)

install(TARGETS dsd
	DESTINATION bin)

