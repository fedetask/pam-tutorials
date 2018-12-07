cmake_minimum_required(VERSION 3.0.0 FATAL_ERROR)

file(GLOB SRC *.c)
file(GLOB HEADERS include/*.h)

project(pam-module)

add_compile_options("-std=c99" "-Wall" "-Wextra" "-pedantic"
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


add_library(main SHARED "${SRC}")

target_link_libraries(main pam)

set_target_properties(main PROPERTIES PREFIX "")

set_target_properties(main PROPERTIES SUFFIX ".so")
