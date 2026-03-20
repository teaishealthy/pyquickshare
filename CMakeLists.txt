cmake_minimum_required(VERSION 3.26)
project(pyquickshare LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Python REQUIRED COMPONENTS Interpreter Development.Module)
find_package(pybind11 REQUIRED CONFIG)
find_package(PkgConfig)


pkg_check_modules(BLUEZ bluez)
if(NOT BLUEZ_FOUND)
    pkg_check_modules(BLUEZ REQUIRED bluetooth)
endif()

pybind11_add_module(_rfcomm pyquickshare/rfcomm/_rfcomm.cpp)
target_include_directories(_rfcomm PRIVATE ${BLUEZ_INCLUDE_DIRS})
target_link_libraries(_rfcomm PRIVATE ${BLUEZ_LINK_LIBRARIES})

install(TARGETS _rfcomm DESTINATION pyquickshare/rfcomm)