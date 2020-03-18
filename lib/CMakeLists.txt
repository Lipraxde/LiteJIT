add_library(LiteJIT LiteJIT.cpp)

target_link_libraries(LiteJIT ${CMAKE_DL_LIBS})

target_include_directories(LiteJIT SYSTEM INTERFACE
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include/>
    $<INSTALL_INTERFACE:${INSTALL_INCLUDE_DIR}>)

install(TARGETS LiteJIT
        EXPORT LiteJITExports
        DESTINATION ${INSTALL_LIB_DIR}
)
