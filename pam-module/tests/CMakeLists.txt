cmake_minimum_required(VERSION 3.0.0 FATAL_ERROR)

file(GLOB PROJ_SOURCES "${PROJECT_SOURCE_DIR}/src/*.c")
file(GLOB PROJ_TESTS "${PROJECT_SOURCE_DIR}/tests/*.cpp")
LIST(REMOVE_ITEM PROJ_SOURCES "${PROJECT_SOURCE_DIR}/src/main.c")

project(pam-module)

add_compile_options("-std=c++11" "-Wall" "-Wextra" "-pedantic"
	"-Wstrict-overflow" "-fno-strict-aliasing" "-D _XOPEN_SOURCE=600" "-g"
	"-pedantic" "-pedantic-errors" "-Wformat=2" "-Wnull-dereference"
	"-Winit-self" "-Wmissing-include-dirs" "-Wshift-overflow=2"
	"-Wswitch-default" "-Wswitch-enum" "-Wunused-parameter"
	"-Wuninitialized" "-Wsuggest-attribute=pure"
	"-Wsuggest-attribute=const" "-Wsuggest-attribute=noreturn"
	"-Wsuggest-attribute=format" "-Wduplicated-cond" "-Wtrampolines"
	"-Wundef" "-Wshadow" "-funsafe-loop-optimizations"
	"-Wunsafe-loop-optimizations" "-Wbad-function-cast" "-Wcast-qual"
	"-Wcast-align" "-Wwrite-strings" "-Wjump-misses-init" "-Wlogical-op"
	"-Waggregate-return" "-Wstrict-prototypes" "-Wold-style-definition"
	"-Wmissing-prototypes" "-Wmissing-declarations" "-Wredundant-decls")


add_executable (tests  ${PROJ_TESTS} ${PROJ_SOURCES})

target_link_libraries(tests curl gtest gtest_main pthread)
