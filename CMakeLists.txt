# Some basics you will need in your cmake file.
cmake_minimum_required(VERSION 3.28.0)
project(pcaptop)
add_executable(pcaptop src/pcaptop.cpp src/cargs.c)
set_property(TARGET pcaptop PROPERTY CXX_STANDARD 17)

# Replace your_path_to_cargs with the path to your cargs copy. 
# This could be something like "${CMAKE_CURRENT_SOURCE_DIR}/lib/cargs".

# Replace example_target with the target name which requires cargs.
# After this, there is no need to specify any include directories.
target_link_libraries(pcaptop pcap ncurses)
