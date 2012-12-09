add_executable(dnd
	context.c
	dnd.c
	dsc.c
	ippool.c
	linkst.c
	main.c
	request.c
	session.c
)

include_directories("${CMAKE_SOURCE_DIR}/../libdnds/src/")
include_directories("${CMAKE_SOURCE_DIR}/../libdnds/src/protocol/")
target_link_libraries(dnd
        ${CMAKE_SOURCE_DIR}/../libdnds/src/libdnds.so
)
