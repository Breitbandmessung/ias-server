cmake_minimum_required(VERSION 3.6)

project(ias-server)

#---------------------------------------------------------------------------------

MESSAGE(STATUS "Looking for pthreads")
FIND_PACKAGE(Threads REQUIRED)
IF (NOT THREADS_FOUND)
	MESSAGE(FATAL_ERROR "ERROR: try -> apt install build-essentials")
ENDIF (NOT THREADS_FOUND)

#---------------------------------------------------------------------------------

MESSAGE(STATUS "Looking for pkg-config")
FIND_PROGRAM(PKG_CONFIG NAMES pkg-config PATHS /usr/bin/)
IF (${PKG_CONFIG} STREQUAL PKG_CONFIG-NOTFOUND)
	MESSAGE(FATAL_ERROR "ERROR: try -> apt install pkg-config")
ENDIF (${PKG_CONFIG} STREQUAL PKG_CONFIG-NOTFOUND)

#---------------------------------------------------------------------------------

MESSAGE(STATUS "Looking for libnopoll")
FIND_PROGRAM(LIBNOPOLL NAMES libnopoll.so PATHS /usr/local/lib/)
IF (${LIBNOPOLL} STREQUAL LIBNOPOLL-NOTFOUND)
	MESSAGE(FATAL_ERROR "ERROR: libnopoll missing")
ENDIF (${LIBNOPOLL} STREQUAL LIBNOPOLL-NOTFOUND)

#---------------------------------------------------------------------------------

set(dir ${CMAKE_CURRENT_SOURCE_DIR}/build)
set(EXECUTABLE_OUTPUT_PATH ${dir} CACHE PATH "Build directory" FORCE)
set(LIBRARY_OUTPUT_PATH ${dir} CACHE PATH "Build directory" FORCE)

set ( CMAKE_VERBOSE_MAKEFILE true )
add_definitions(-std=c++14)
add_definitions(-Wall)
add_definitions(-Wextra)
add_definitions(-DIAS_SERVER)
add_definitions("$$(pkg-config nopoll --cflags)")
add_definitions("$$(pkg-config nopoll --libs)")

set(IAS_SERVER true)

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    MESSAGE(STATUS "Using CMAKE_BUILD_TYPE Release")
else()
MESSAGE(STATUS "Using CMAKE_BUILD_TYPE Debug, adding debug symbols flag -g")
	add_definitions(-g)
endif()

add_subdirectory (src)
add_subdirectory (${CMAKE_CURRENT_SOURCE_DIR}/ias-libtool ${CMAKE_CURRENT_BINARY_DIR}/ias-libtool)

INSTALL(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/ias-server DESTINATION bin )
INSTALL(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/libiastool.so DESTINATION /usr/lib )

INCLUDE (InstallRequiredSystemLibraries)
SET (CPACK_COMPONENTS_ALL Libraries ApplicationData)

SET (CPACK_SET_DESTDIR ON)
SET (CPACK_PACKAGING_INSTALL_PREFIX "/tmp")
SET (CPACK_GENERATOR "DEB")

SET (CPACK_DEBIAN_PACKAGE_PRIORITY "high")
SET (CPACK_DEBIAN_PACKAGE_SECTION "measurement")
SET (CPACK_DEBIAN_ARCHITECTURE ${CMAKE_SYSTEM_PROCESSOR})
set (CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)

SET (CPACK_PACKAGE_DESCRIPTION "ias-server")
SET (CPACK_PACKAGE_DESCRIPTION_SUMMARY "ias-server")
SET (CPACK_DEBIAN_PACKAGE_MAINTAINER "zafaco GmbH")
SET (CPACK_PACKAGE_FILE_NAME "${CMAKE_PROJECT_NAME}_${CPACK_DEBIAN_ARCHITECTURE}")

SET (CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA debian/postinst;debian/preinst;debian/prerm)

INCLUDE(CPack)