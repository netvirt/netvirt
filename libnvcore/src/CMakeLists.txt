set(CMAKE_C_FLAGS "-g -W -Wall ${compiler_options}")

add_subdirectory(tests)

set(NVCORE_SRCS
	bitv.c
	log.c
	pki.c
)

add_library(nvcore ${NVCORE_SRCS})

