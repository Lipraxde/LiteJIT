cmake_minimum_required (VERSION 3.10)
project(LiteJIT LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)

set(LITEJIT_MAJOR_VERSION 0)
set(LITEJIT_MINOR_VERSION 1)
set(LITEJIT_PATCH_VERSION 0)
set(LITEJIT_VERSION ${LITEJIT_MAJOR_VERSION}.${LITEJIT_MINOR_VERSION}.${LITEJIT_PATCH_VERSION})

set(INSTALL_INCLUDE_DIR include CACHE PATH "Installation directory for header files" FORCE)
set(INSTALL_LIB_DIR lib CACHE PATH "Installation directory for libraries" FORCE)
set(INSTALL_CMAKE_DIR lib/cmake/litejit CACHE PATH "Installation directory for CMake files" FORCE)

# Make relative paths absolute (needed later on)
foreach(p LIB BIN INCLUDE CMAKE SCRIPT BUILDER_SCRIPT)
    set(var INSTALL_${p}_DIR)
    if(NOT IS_ABSOLUTE "${${var}}")
        set(${var} "${CMAKE_INSTALL_PREFIX}/${${var}}")
    endif()
endforeach()

if (NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    message (STATUS "Setting build type to 'Debug' as none was specified.")
    set (CMAKE_BUILD_TYPE Debug CACHE STRING "Choose the type of build." FORCE)
    set_property (CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "MinSizeRel" "RelWithDebInfo")
endif ()

# Add cmake module path
set(CMAKE_MODULE_PATH
    ${CMAKE_MODULE_PATH}
    "${PROJECT_SOURCE_DIR}/cmake"
)

add_compile_options(-Wall)


if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    # LiteJIT is a top-level project, do not ignore errors for debugging
    set(DEFAULT_LITEJIT_IGNORE_ERR FALSE)
else()
    # LiteJIT is not a top-level project, ignore errors for using
    set(DEFAULT_LITEJIT_IGNORE_ERR TRUE)
endif()

option(LITEJIT_IGNORE_ERROR "Ignore error in LiteJIT" ${DEFAULT_LITEJIT_IGNORE_ERR})
option(LITEJIT_DISABLE_LOOKUP "Disable lookup function to avoid using internal symbol table which is a string map" FALSE)
configure_file(${PROJECT_SOURCE_DIR}/cmake/litejit-config.h.in
               ${PROJECT_BINARY_DIR}/include/litejit-config.h)

# Add include
include_directories(include/)
include_directories(${PROJECT_BINARY_DIR}/include/)

# Install include header
install(DIRECTORY   include/
        DESTINATION ${INSTALL_INCLUDE_DIR}
)
install(DIRECTORY   ${PROJECT_BINARY_DIR}include/
        DESTINATION ${INSTALL_INCLUDE_DIR}
)

# Add lib & exe
add_subdirectory(lib/)
add_subdirectory(example/)

# Uninstall target
if(NOT TARGET uninstall)
    configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/cmake/cmake_uninstall.cmake.in"
        "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
        IMMEDIATE @ONLY)

    add_custom_target(uninstall
        COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)
endif()

# Add all targets to the build-tree export set
export(EXPORT LiteJITExports FILE "${PROJECT_BINARY_DIR}/LiteJITExports.cmake")

# Export the package for use from the build-tree
# (this registers the build-tree with a global CMake-registry)
export(PACKAGE LiteJIT)

# Create the LiteJITConfig.cmake and LiteJITConfigVersion files
file(RELATIVE_PATH REL_INCLUDE_DIR "${INSTALL_CMAKE_DIR}" "${INSTALL_INCLUDE_DIR}")
# ... for the build tree
set(CONF_INCLUDE_DIRS ${PROJECT_SOURCE_DIR}/include)
configure_file(${PROJECT_SOURCE_DIR}/cmake/LiteJITConfig.cmake.in
  "${PROJECT_BINARY_DIR}/LiteJITConfig.cmake" @ONLY)
# ... for the install tree
set(CONF_INCLUDE_DIRS "\${LITEJIT_CMAKE_DIR}/${REL_INCLUDE_DIR}")
configure_file(${PROJECT_SOURCE_DIR}/cmake/LiteJITConfig.cmake.in
  "${PROJECT_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/LiteJITConfig.cmake" @ONLY)
# ... for both
configure_file(${PROJECT_SOURCE_DIR}/cmake/LiteJITConfigVersion.cmake.in
  "${PROJECT_BINARY_DIR}/LiteJITConfigVersion.cmake" @ONLY)

# Install the LiteJITConfig.cmake and LiteJITConfigVersion.cmake
install(FILES ${PROJECT_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/LiteJITConfig.cmake
        ${PROJECT_BINARY_DIR}/LiteJITConfigVersion.cmake
        DESTINATION ${INSTALL_CMAKE_DIR})

# Install the export set for use with the install-tree
install(EXPORT LiteJITExports DESTINATION ${INSTALL_CMAKE_DIR})
