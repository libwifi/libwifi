cmake_minimum_required(VERSION 3.18)

project(wifi DESCRIPTION "802.11 Parsing / Generation library" VERSION 0.1)

execute_process(COMMAND git rev-parse --abbrev-ref HEAD OUTPUT_STRIP_TRAILING_WHITESPACE OUTPUT_VARIABLE GITBRANCH)
execute_process(COMMAND git log -1 --pretty=format:%h OUTPUT_STRIP_TRAILING_WHITESPACE OUTPUT_VARIABLE GITHASH)
execute_process(COMMAND date OUTPUT_STRIP_TRAILING_WHITESPACE OUTPUT_VARIABLE BUILDTIME)
set(LIBWIFI_VERSION "0.0.3")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu17")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pedantic -Wno-language-extension-token")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wmissing-prototypes -Wstrict-prototypes")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector-strong")

message(" ")
message(" _  _  _                _   __  _   ")
message("| |(_)| |              (_) / _|(_)  ")
message("| | _ | |__  __      __ _ | |_  _   ")
message("| || || '_ \\ \\ \\ /\\ / /| ||  _|| |  ")
message("| || || |_| | \\ V  V / | || |  | |  ")
message("|_||_||_.__/   \\_/\\_/  |_||_|  |_|  ")
message("-----------------------------------")
message("802.11 Parsing / Generation Library")
message("Version: ${LIBWIFI_VERSION}, Git: ${GITBRANCH} (${GITHASH}), Time: ${BUILDTIME}")
message("Compiler: ${CMAKE_C_COMPILER_ID} ${CMAKE_C_COMPILER_VERSION}")

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    message("Building for Debug")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ggdb -O0")
    add_compile_definitions(LIBWIFI_VERSION="dev-${GITBRANCH}-${GITHASH}")
else()
    message("Building for Release")
    add_compile_definitions(LIBWIFI_VERSION="${LIBWIFI_VERSION}")
endif(CMAKE_BUILD_TYPE STREQUAL "Debug")

message(" ")

file(GLOB_RECURSE libwifi_src
    "src/libwifi/*.h"
    "src/libwifi/*.c"
)

add_library(wifi SHARED ${libwifi_src})

set_target_properties(wifi PROPERTIES LINKER_LANGUAGE C)
set_target_properties(wifi PROPERTIES VERSION ${LIBWIFI_VERSION})
set_target_properties(wifi PROPERTIES SOVERSION 0)
set_target_properties(wifi PROPERTIES PUBLIC_HEADER src/libwifi.h)

install(DIRECTORY src/libwifi/core/ DESTINATION /usr/include/libwifi/core FILES_MATCHING PATTERN "*.h")
install(DIRECTORY src/libwifi/parse/ DESTINATION /usr/include/libwifi/parse FILES_MATCHING PATTERN "*.h")
install(DIRECTORY src/libwifi/gen/ DESTINATION /usr/include/libwifi/gen FILES_MATCHING PATTERN "*.h")
install(TARGETS wifi LIBRARY DESTINATION /usr/lib PUBLIC_HEADER DESTINATION /usr/include)

add_custom_target(uninstall COMMAND rm -rf /usr/include/libwifi; rm -rf /usr/include/libwifi.h)
add_custom_target(libinstall COMMAND cp libwifi.so* /usr/lib)
