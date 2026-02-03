# Some basics you will need in your cmake file.
cmake_minimum_required(VERSION 3.28.0)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
project(pcaptop)
# set(CMAKE_BUILD_TYPE Debug)
add_executable(pcaptop src/pcaptop.cpp src/cargs.c)
set_property(TARGET pcaptop PROPERTY CXX_STANDARD 17)

# Replace example_target with the target name which requires cargs.
# After this, there is no need to specify any include directories.
target_link_libraries(pcaptop pcap ncurses)
