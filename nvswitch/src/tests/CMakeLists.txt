set(CMAKE_C_FLAGS "-g -W -Wall ${compiler_options}")
set(CMAKE_CXX_FLAGS "-g -W -Wall ${compiler_options}")

add_executable(test1_switch test1_switch.c)
add_test(test1_switch test1_switch)

add_executable(test_linkst test_linkst.c ../linkst.c)
add_test(test_linkst test_linkst)
