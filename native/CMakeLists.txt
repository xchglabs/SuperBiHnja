cmake_minimum_required(VERSION 3.28 FATAL_ERROR)

project(arch_sh4)

if(NOT BN_INTERNAL_BUILD)
	set(BN_API_PATH "/tmp/bn-api" CACHE PATH "Path to binaryninja-api")
	add_subdirectory(${BN_API_PATH} ${CMAKE_BINARY_DIR}/api)
endif()

file(GLOB SOURCES CONFIGURE_DEPENDS
	*.cpp
	*.h)

if(DEMO)
    add_library(arch_sh4 STATIC ${SOURCES})
else()
    add_library(arch_sh4 SHARED ${SOURCES})
endif()

target_include_directories(arch_sh4
	PRIVATE ${PROJECT_SOURCE_DIR})

if(WIN32)
	target_link_directories(arch_sh4
		PRIVATE ${BN_INSTALL_DIR})
	target_link_libraries(arch_sh4 binaryninjaapi binaryninjacore)
else()
	target_link_libraries(arch_sh4 binaryninjaapi)
endif()

set_target_properties(arch_sh4 PROPERTIES
	CXX_STANDARD 20
	CXX_STANDARD_REQUIRED ON
	CXX_VISIBILITY_PRESET hidden
	VISIBILITY_INLINES_HIDDEN ON
	POSITION_INDEPENDENT_CODE ON)

if(BN_INTERNAL_BUILD)
	plugin_rpath(arch_sh4)
	set_target_properties(arch_sh4 PROPERTIES
		LIBRARY_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR}
		RUNTIME_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR})
endif()
