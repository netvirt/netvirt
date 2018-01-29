set(CMAKE_C_FLAGS "-I/usr/local/include -L/usr/local/lib -g -W -Wall -DHAVE_VA_COPY ${compiler_options}")

add_subdirectory(tests)

if (CMAKE_SYSTEM_NAME MATCHES "Linux")
	set(compat_src bsd-asprintf.c)
endif (CMAKE_SYSTEM_NAME MATCHES "Linux")

if (APPLE)
  if (NOT OPENSSL_ROOT_DIR)
    set(OPENSSL_ROOT_DIR /usr/local/opt/openssl)
  endif()
  include_directories("${OPENSSL_ROOT_DIR}/include")
  link_directories("${OPENSSL_ROOT_DIR}/lib")
endif()

if (WIN32)
	include_directories("${LIBRESSL_ROOT_DIR}/include/" "${LIBEVENT_ROOT_DIR}/include/" "${CMAKE_SOURCE_DIR}/libnv/src/")
	set(compat_src bsd-asprintf.c err.c)
endif()

set(NV_SRCS
	bitv.c
	log.c
	pki.c

	${compat_src}
)

add_library(nv ${NV_SRCS})

