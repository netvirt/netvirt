set(CMAKE_C_FLAGS "-g -W -Wall ${compiler_options}")
set(CMAKE_CXX_FLAGS "-g -W -Wall ${compiler_options}")

add_executable(test1_dnc test1_dnc.c)
add_test(test1_dnc test1_dnc)
