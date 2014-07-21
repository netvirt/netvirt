set(CMAKE_C_FLAGS "-g -W -Wall ${compiler_options}")
set(CMAKE_CXX_FLAGS "-g -W -Wall ${compiler_options}")

add_executable(test1_ctrler test1_ctrler.c)
add_test(test1_ctrler test1_ctrler)

add_executable(test_ippool test_ippool.c ../ippool.c)
add_test(test_ippool test_ippool)
