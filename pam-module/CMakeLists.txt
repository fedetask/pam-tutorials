cmake_minimum_required(VERSION 3.0.0 FATAL_ERROR)

project(pam-module)

SET( CMAKE_EXPORT_COMPILE_COMMANDS ON )

include_directories(
	src/include/
	tests/include/
	)

add_subdirectory (src)

add_subdirectory (tests)
