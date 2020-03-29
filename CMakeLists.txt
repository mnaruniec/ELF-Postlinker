cmake_minimum_required(VERSION 3.15)
project(zadanie1)

set(CMAKE_CXX_STANDARD 14)

add_executable(zadanie1 postlinker.cpp files.cpp files.h relocations.cpp relocations.h constants.h structuring.cpp structuring.h)