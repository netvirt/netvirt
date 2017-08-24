set(CMAKE_C_FLAGS "-g -W -Wall ${compiler_options}")

add_subdirectory(tests)

if (CMAKE_SYSTEM_NAME MATCHES "Linux")
	set(compat_src bsd-asprintf.c)
endif (CMAKE_SYSTEM_NAME MATCHES "Linux")

set(NVCORE_SRCS
	bitv.c
	log.c
	pki.c

	${compat_src}
)

add_library(nvcore ${NVCORE_SRCS})

