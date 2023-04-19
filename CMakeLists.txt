cmake_minimum_required(VERSION 3.25)
project(Lab_6_server)

set(CMAKE_CXX_STANDARD 17)

add_executable(Lab_6_server main.cpp sha-1.h)
target_link_libraries(Lab_6_server Ws2_32.lib)