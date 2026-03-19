cmake_minimum_required(VERSION 3.26)
project(bluez_rfcomm LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Python REQUIRED COMPONENTS Interpreter Development.Module)
find_package(pybind11 REQUIRED CONFIG)

# Try "bluez" first (Arch Linux), fall back to "bluetooth" (Debian/Ubuntu).
# Note: "pkg-config bluetooth" fails on Arch even when libbluetooth is installed;
# the correct module name there is "bluez".
find_package(PkgConfig REQUIRED)
pkg_check_modules(BLUEZ bluez)
if(NOT BLUEZ_FOUND)
    pkg_check_modules(BLUEZ REQUIRED bluetooth)
endif()

# Hard-coded fallback if pkg-config is entirely absent:
# set(BLUEZ_INCLUDE_DIRS /usr/include)
# set(BLUEZ_LINK_LIBRARIES bluetooth)

pybind11_add_module(_rfcomm src/bluez_rfcomm/_rfcomm.cpp)
target_include_directories(_rfcomm PRIVATE ${BLUEZ_INCLUDE_DIRS})
target_link_libraries(_rfcomm PRIVATE ${BLUEZ_LINK_LIBRARIES})
install(TARGETS _rfcomm DESTINATION bluez_rfcomm)
