cmake_minimum_required(VERSION 3.28)


set (PROJECT_TYPE_EXECUTABLE "exe")

set (PROJECT_TYPE_STATIC_LIBRARY "static-lib")

set (PROJECT_NAME "Network")

project(${PROJECT_NAME} LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set (PROJECT_SOURCES
	# LIST SOURCE FILES HERE
	ConnectionSocket.cpp
	DNS.cpp
	main.cpp)

set( PROJECT_HEADERS
  # LIST HEADER FILES HERE
  ConnectionSocket.h
  DNS.h 
)

set (PROJECT_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR})

set (PROJECT_DEFINES)

set (PROJECT_TYPE "exe")


if (${PROJECT_TYPE} STREQUAL ${PROJECT_TYPE_EXECUTABLE})
	add_executable(${PROJECT_NAME} ${PROJECT_SOURCES} ${PROJECT_HEADERS})
elseif (${PROJECT_TYPE} STREQUAL ${PROJECT_TYPE_STATIC_LIBRARY})
  add_library(${PROJECT_NAME} STATIC ${PROJECT_SOURCES} ${PROJECT_HEADERS})
endif()


source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR}
    PREFIX "Source Files"
    FILES ${PROJECT_SOURCES}
)

source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR}
    PREFIX "Header Files"
    FILES ${PROJECT_HEADERS}
)

target_compile_definitions(${PROJECT_NAME} PRIVATE ${PROJECT_DEFINES})
target_include_directories (${PROJECT_NAME} PRIVATE ${PROJECT_INCLUDES})

if (WIN32)
    target_link_libraries(${PROJECT_NAME} PRIVATE Ws2_32 Iphlpapi)
    target_compile_definitions(${PROJECT_NAME}
        PRIVATE
            _WIN32_WINNT=0x0601
    )
endif()
