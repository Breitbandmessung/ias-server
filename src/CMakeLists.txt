cmake_minimum_required(VERSION 3.6)

project(ias-server)

#---------------------------------------------------------------------------------

include_directories(${CMAKE_CURRENT_BINARY_DIR})

add_executable(ias-server
        ias_server.cpp
        tcpserver.cpp
        tcphandler.cpp
        tcptraceroutehandler.cpp
        udpserver.cpp
)

TARGET_LINK_LIBRARIES(ias-server
        ${CMAKE_THREAD_LIBS_INIT}
        iastool
        -llog4cpp
        -lssl
        -lcrypto
        -lnopoll
)

INCLUDE(CPack)