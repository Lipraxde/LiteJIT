add_library(LiteJIT LiteJIT.cpp)

target_link_libraries(LiteJIT ${CMAKE_DL_LIBS})

install(TARGETS LiteJIT
	EXPORT LiteJITExports
        DESTINATION ${INSTALL_LIB_DIR}
)
