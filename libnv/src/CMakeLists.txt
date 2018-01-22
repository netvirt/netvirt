set(CMAKE_C_FLAGS "-I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib  -I/usr/local/include -L/usr/local/lib -g -W -Wall -DHAVE_VA_COPY ${compiler_options}")

add_subdirectory(tests)

if (CMAKE_SYSTEM_NAME MATCHES "Linux")
	set(compat_src bsd-asprintf.c)
endif (CMAKE_SYSTEM_NAME MATCHES "Linux")

if (WIN32)
	set(compat_src bsd-asprintf.c err.c)
endif()

set(NV_SRCS
	bitv.c
	log.c
	pki.c

	${compat_src}
)

add_library(nv ${NV_SRCS})

