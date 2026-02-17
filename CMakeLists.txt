cmake_minimum_required(VERSION 3.14)
project(bob LANGUAGES C ASM CXX)
set (CMAKE_CXX_STANDARD 17) # redis-plus-plus requires C++17

if(CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
	add_definitions(-D_CRT_SECURE_NO_WARNINGS)
	SET(CXX_BOB_FLAGS "/arch:AVX2")
else ()
	SET(CXX_BOB_FLAGS "-Wunused-variable -mavx2")
endif()
SET(CMAKE_C_FLAGS  "${CMAKE_C_FLAGS} ${CXX_BOB_FLAGS}")
SET(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} ${CXX_BOB_FLAGS}")

# --- Fetch and configure dependencies ---
include(FetchContent)

# redis-plus-plus
FetchContent_Declare(
  redis-plus-plus
  GIT_REPOSITORY https://github.com/sewenew/redis-plus-plus.git
  GIT_TAG        1.3.15 # Using a specific tag for reproducibility
)
# redis-plus-plus specific options
set(REDIS_PLUS_PLUS_USE_HIREDIS_STATIC_LIB ON CACHE BOOL "" FORCE) # Avoid runtime dependency on hiredis
set(REDIS_PLUS_PLUS_BUILD_TEST OFF CACHE BOOL "" FORCE)
set(REDIS_PLUS_PLUS_BUILD_STATIC ON CACHE BOOL "" FORCE)
set(REDIS_PLUS_PLUS_BUILD_SHARED OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(redis-plus-plus)
include_directories(${redis-plus-plus_SOURCE_DIR}/include)

# spdlog
FetchContent_Declare(
    spdlog
    GIT_REPOSITORY https://github.com/gabime/spdlog.git
    GIT_TAG        v1.12.0
)
FetchContent_MakeAvailable(spdlog)
include_directories(${spdlog_SOURCE_DIR}/include)
# cxxopts
FetchContent_Declare(
    cxxopts
    GIT_REPOSITORY https://github.com/jarro2783/cxxopts.git
    GIT_TAG        v3.1.1
)
FetchContent_MakeAvailable(cxxopts)
include_directories(${cxxopts_SOURCE_DIR}/include)

# gtest
FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG        v1.14.0
)
FetchContent_MakeAvailable(googletest)

# zstd
FetchContent_Declare(
		zstd
		GIT_REPOSITORY https://github.com/facebook/zstd.git
		GIT_TAG v1.5.7
        SOURCE_SUBDIR build/cmake
)
set(ZSTD_BUILD_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ZSTD_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(ZSTD_BUILD_STATIC ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(zstd)
include_directories(${zstd_SOURCE_DIR}/lib)

# Choose the correct zstd target name depending on how it's defined.
if (TARGET libzstd_static)
  set(ZSTD_TARGET libzstd_static)
elseif (TARGET zstd::libzstd_static)
  set(ZSTD_TARGET zstd::libzstd_static)
elseif (TARGET zstd::libzstd_shared)
  set(ZSTD_TARGET zstd::libzstd_shared)
else()
  message(FATAL_ERROR "zstd target not found; expected libzstd_static or zstd::libzstd_static")
endif()

find_package(jsoncpp REQUIRED)
get_target_property(JSONCPP_INCLUDE_DIRS jsoncpp_lib INTERFACE_INCLUDE_DIRECTORIES)
if(JSONCPP_INCLUDE_DIRS)
	include_directories(${JSONCPP_INCLUDE_DIRS})
endif()
set(JSONCPP_TARGET jsoncpp_lib)

# drogon
FetchContent_Declare(
		drogon
		GIT_REPOSITORY https://github.com/drogonframework/drogon.git
		GIT_TAG v1.8.7
)
set(BUILD_EXAMPLES OFF CACHE BOOL "Build Drogon examples" FORCE)
set(BUILD_CTL OFF CACHE BOOL "Build drogon_ctl" FORCE)
set(BUILD_TESTING OFF CACHE BOOL "Build Drogon tests" FORCE)
set(BUILD_DOC OFF CACHE BOOL "Build Drogon documentation" FORCE)
FetchContent_MakeAvailable(drogon)
include_directories(${drogon_SOURCE_DIR}/lib/inc)

# Get git commit hash
execute_process(
    COMMAND git rev-parse HEAD
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    OUTPUT_VARIABLE GIT_COMMIT_HASH
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
)
if(NOT GIT_COMMIT_HASH)
    set(GIT_COMMIT_HASH "unknown")
endif()

# Get compiler name and version
set(COMPILER_NAME "${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")

# Pass to compiler definitions
add_compile_definitions(
    GIT_COMMIT_HASH="${GIT_COMMIT_HASH}"
    COMPILER_NAME="${COMPILER_NAME}"
)

# Check for AVX2 support
include(CheckCXXCompilerFlag)
CHECK_CXX_COMPILER_FLAG("-mavx2" COMPILER_SUPPORTS_AVX2)
if (NOT COMPILER_SUPPORTS_AVX2)
	message(WARNING "AVX2 not supported by the compiler")
endif ()

# --- Project Sources ---
SET(FILES
		${CMAKE_SOURCE_DIR}/connection/connection.cpp
		${CMAKE_SOURCE_DIR}/connection/connectionPool.cpp
		${CMAKE_SOURCE_DIR}/connection/NodeIntroducer.cpp
        ${CMAKE_SOURCE_DIR}/database/db.cpp
		${CMAKE_SOURCE_DIR}/database/garbageCleaner.cpp
		${CMAKE_SOURCE_DIR}/Logger.cpp
		${CMAKE_SOURCE_DIR}/DataProcessors.cpp
		${CMAKE_SOURCE_DIR}/IOProcessor.cpp
		${CMAKE_SOURCE_DIR}/LoggingEventProcessor.cpp
		${CMAKE_SOURCE_DIR}/QubicServer.cpp
		${CMAKE_SOURCE_DIR}/QubicIndexer.cpp
		${CMAKE_SOURCE_DIR}/Config.cpp
		${CMAKE_SOURCE_DIR}/bob.cpp
		${CMAKE_SOURCE_DIR}/GlobalVar.cpp
		${CMAKE_SOURCE_DIR}/LogEvent.cpp
		${CMAKE_SOURCE_DIR}/RESTAPI/bobAPI.cpp
		${CMAKE_SOURCE_DIR}/RESTAPI/ApiHelpers.cpp
		${CMAKE_SOURCE_DIR}/RESTAPI/querySmartContract.cpp
		${CMAKE_SOURCE_DIR}/RESTAPI/RESTServer.cpp
		${CMAKE_SOURCE_DIR}/RESTAPI/QubicRpcMapper.cpp
		${CMAKE_SOURCE_DIR}/RESTAPI/QubicRpcWebSocket.cpp
		${CMAKE_SOURCE_DIR}/RESTAPI/QubicRpcMethods.cpp
		${CMAKE_SOURCE_DIR}/RESTAPI/QubicSubscriptionManager.cpp
		${CMAKE_SOURCE_DIR}/RESTAPI/QubicRpcHandler.cpp
)

add_library(XKCP_avx2 STATIC XKCP/KangarooTwelve.c
		XKCP/KeccakP-1600-AVX2.s
		XKCP/KeccakP-1600-times4-AVX2.c
		                     XKCP/TurboSHAKE.c
)

# Create a library from the source files to be shared between the main executable and tests
add_library(bob_lib STATIC ${FILES})
target_link_libraries(bob_lib PRIVATE redis++_static hiredis spdlog::spdlog cxxopts::cxxopts
		${ZSTD_TARGET} XKCP_avx2 drogon ${JSONCPP_TARGET})


# --- Executable and Linking ---
ADD_EXECUTABLE(bob main.cpp)
ADD_EXECUTABLE(pop10 pop10.cpp)
target_link_libraries(bob PRIVATE bob_lib)
target_link_libraries(pop10 PRIVATE bob_lib)

# --- Testing with Google Test ---
enable_testing()
include(GoogleTest)
include_directories(${CMAKE_SOURCE_DIR}/)
file(GLOB TEST_FILES "tests/*.cpp")
add_executable(bob_tests ${TEST_FILES})
target_link_libraries(bob_tests PRIVATE XKCP_avx2 bob_lib gtest_main redis++_static hiredis spdlog::spdlog)
gtest_discover_tests(bob_tests)

# Copy configuration file after building bob
add_custom_command(
		TARGET bob POST_BUILD
		COMMAND ${CMAKE_COMMAND} -E copy_if_different
		${CMAKE_SOURCE_DIR}/default_config_bob.json
		${CMAKE_BINARY_DIR}/bob.json
)

# Copy OpenAPI spec to build directory
add_custom_command(
		TARGET bob POST_BUILD
		COMMAND ${CMAKE_COMMAND} -E copy_if_different
		${CMAKE_SOURCE_DIR}/RESTAPI/openapi.json
		${CMAKE_BINARY_DIR}/openapi.json
)
