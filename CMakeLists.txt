# marmotVM CMakeLists.txt
# Build: mkdir build && cd build && cmake -DCMAKE_C_COMPILER=clang .. && make
# Python: cmake -DBUILD_PYTHON=ON -DCMAKE_C_COMPILER=clang ..

cmake_minimum_required(VERSION 3.20)
project(marmotVM VERSION 1.0.0 LANGUAGES C)

# Use Clang compiler
set(CMAKE_C_COMPILER "clang" CACHE STRING "C compiler" FORCE)
set(CMAKE_CXX_COMPILER "clang++" CACHE STRING "C++ compiler" FORCE)

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Compiler flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wpedantic")
set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG")
set(CMAKE_C_FLAGS_DEBUG "-g -O0 -DDEBUG")

# Source files
set(MICROVM_SOURCES
    src/microvm.c
)

# Header files
set(MICROVM_HEADERS
    include/microvm.h
)

# Add the library
add_library(microvm STATIC ${MICROVM_SOURCES} ${MICROVM_HEADERS})

target_include_directories(microvm PUBLIC 
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

# Platform-specific libraries
if(APPLE)
    target_link_libraries(microvm pthread)
elseif(LINUX)
    target_link_libraries(microvm pthread)
elseif(WINDOWS)
    # ws2_32 is linked in source
endif()

# Enable debug symbols if requested
option(ENABLE_DEBUG "Enable debug symbols" OFF)
if(ENABLE_DEBUG)
    target_compile_options(microvm PRIVATE -g -O0)
endif()

# Installation
install(TARGETS microvm ARCHIVE DESTINATION lib)
install(FILES ${MICROVM_HEADERS} DESTINATION include)

# Python binding option
option(BUILD_PYTHON "Build Python bindings" OFF)
if(BUILD_PYTHON)
    find_package(Python3 COMPONENTS Interpreter Development.Module REQUIRED)
    
    # Get Python include and library paths
    execute_process(
        COMMAND ${Python3_EXECUTABLE} -c "import sysconfig; print(sysconfig.get_path('include'))"
        OUTPUT_VARIABLE Python3_INCLUDE_DIR
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    execute_process(
        COMMAND ${Python3_EXECUTABLE} -c "import sysconfig; print(sysconfig.get_config_var('LIBDIR'))"
        OUTPUT_VARIABLE Python3_LIB_DIR
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    
    message(STATUS "Python include: ${Python3_INCLUDE_DIR}")
    message(STATUS "Python lib: ${Python3_LIB_DIR}")
    
    # Build Python module as shared library
    set(PYTHON_SOURCES src/microvm_python.c)
    
    # Create the Python extension module
    add_library(marmotvm_module MODULE ${PYTHON_SOURCES})
    
    target_include_directories(marmotvm_module PRIVATE 
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${Python3_INCLUDE_DIR}
    )
    
    target_link_libraries(marmotvm_module PRIVATE
        microvm
        pthread
    )
    if(TARGET Python3::Module)
        target_link_libraries(marmotvm_module PRIVATE Python3::Module)
    elseif(TARGET Python3::Python)
        target_link_libraries(marmotvm_module PRIVATE Python3::Python)
    endif()

    # On macOS, extension modules commonly resolve Python API symbols at runtime.
    if(APPLE)
        target_link_options(marmotvm_module PRIVATE "-undefined" "dynamic_lookup")
    endif()
    
    # Set module name to match Python import (marmotVM.so)
    set_target_properties(marmotvm_module PROPERTIES 
        PREFIX ""
        OUTPUT_NAME "marmotVM"
        # Ensure the produced shared library matches Python's expected
        # ABI-tagged extension suffix (e.g. .cpython-312-darwin.so).
        SUFFIX "${Python3_EXTENSION_MODULE_SUFFIX}"
    )
    
    # Installation
    install(TARGETS marmotvm_module 
            LIBRARY DESTINATION ${Python3_SITEARCH}
            COMPONENT RuntimeLibraries)
    
    message(STATUS "Python module will be installed to: ${Python3_SITEARCH}")
endif()

# Tests
enable_testing()
add_executable(microvm_test tests/test.c)
target_link_libraries(microvm_test PRIVATE microvm pthread)
target_include_directories(microvm_test PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
add_test(NAME microvm_test COMMAND microvm_test)
