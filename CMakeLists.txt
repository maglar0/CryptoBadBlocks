cmake_minimum_required(VERSION 3.10)
project(CryptoBadBlocks)

set(CMAKE_CXX_STANDARD 17)

# Set output directory for the executable
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Define a macro to identify the platform
if(APPLE)
    add_definitions(-DMAC=1)
    # No need to link CommonCrypto explicitly on macOS
    set(PLATFORM_LIBS "-framework Security")
elseif(UNIX)
    add_definitions(-DMAC=0)
    # Assume OpenSSL on Unix-like platforms (Linux, BSD)
    find_package(OpenSSL REQUIRED)
    set(PLATFORM_LIBS OpenSSL::Crypto)
elseif(WIN32)
    add_definitions(-DMAC=0)
    # Use Windows built-in crypto library
    set(PLATFORM_LIBS bcrypt)
else()
    message(FATAL_ERROR "Unsupported platform")
endif()

# Add the src directory and set output file name
add_executable(CryptoBadBlocks src/main.cpp)

# Link platform-specific libraries
target_link_libraries(CryptoBadBlocks ${PLATFORM_LIBS})