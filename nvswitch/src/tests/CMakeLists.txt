set(CMAKE_C_FLAGS "-g -W -Wall ${compiler_options}")
set(CMAKE_CXX_FLAGS "-g -W -Wall ${compiler_options}")

add_executable(test1_dnd test1_dnd.c)
add_test(test1_dnd test1_dnd)
