cmake_minimum_required(VERSION 3.24)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

project(BpfBackTrace DESCRIPTION "Can we get a stack trace using BPF?")


add_executable(load load.c)
target_link_libraries(load bpf)
add_dependencies(load bpf)

add_custom_target(bpf
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_OBJECTS:bpf_st> ${CMAKE_BINARY_DIR}/bpf_st.o
    DEPENDS bpf_st)

add_library(bpf_st OBJECT bpf_st.c)
target_compile_options(bpf_st PUBLIC -c -g -O2 -target bpf)

