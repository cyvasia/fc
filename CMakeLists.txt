#
# Defines fc library target.

if (POLICY CMP0025)
    # Compiler id for Apple Clang is now AppleClang
    cmake_policy(SET CMP0025 NEW)
endif()

if (POLICY CMP0048)
    # The ``project()`` command manages VERSION variables.
    cmake_policy(SET CMP0048 NEW)
endif()

CMAKE_MINIMUM_REQUIRED( VERSION 3.10.2 )
PROJECT( fc LANGUAGES CXX C )

MESSAGE(STATUS "Configuring project fc located in: ${CMAKE_CURRENT_SOURCE_DIR}")

# Compile in C++11 mode
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Compile in C99 mode
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Setup module path to make visible used CMake extensions
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/GitVersionGen")
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/CMakeModules")

INCLUDE(GetPrerequisites)
INCLUDE( VersionMacros )
INCLUDE( SetupTargetMacros )
INCLUDE(GetGitRevisionDescription)

get_git_head_revision(GIT_REFSPEC FC_GIT_REVISION_SHA)
get_git_unix_timestamp(FC_GIT_REVISION_UNIX_TIMESTAMP)

SET( DEFAULT_HEADER_INSTALL_DIR include/\${target} )
SET( DEFAULT_LIBRARY_INSTALL_DIR lib/ )
SET( DEFAULT_EXECUTABLE_INSTALL_DIR bin/ )
SET( CMAKE_DEBUG_POSTFIX _debug )
SET( BUILD_SHARED_LIBS NO )
SET( ECC_IMPL secp256k1 CACHE STRING "secp256k1 or openssl or mixed" )

IF( ECC_IMPL STREQUAL openssl )
  SET( ECC_REST src/crypto/elliptic_impl_pub.cpp )
ELSE( ECC_IMPL STREQUAL openssl )
  SET( ECC_LIB secp256k1 )
  IF( ECC_IMPL STREQUAL mixed )
    SET( ECC_REST src/crypto/elliptic_impl_priv.cpp src/crypto/elliptic_impl_pub.cpp )
  ELSE( ECC_IMPL STREQUAL mixed )
    SET( ECC_REST src/crypto/elliptic_impl_priv.cpp )
  ENDIF( ECC_IMPL STREQUAL mixed )
ENDIF( ECC_IMPL STREQUAL openssl )

# Configure secp256k1-zkp
if ( WIN32 )
    # autoconf won't work here, hard code the defines
    set( SECP256K1_DIR "${CMAKE_CURRENT_SOURCE_DIR}/vendor/secp256k1-zkp" )

    file( GLOB SECP256K1_SOURCES "${SECP256K1_DIR}/src/secp256k1.c" )
    add_library( secp256k1 ${SECP256K1_SOURCES} )

    target_include_directories( secp256k1 PRIVATE "${SECP256K1_DIR}" PUBLIC "${SECP256K1_DIR}/include" )

    set( SECP256K1_BUILD_DEFINES
        USE_FIELD_10X26
        USE_FIELD_INV_BUILTIN
        USE_NUM_NONE
        USE_SCALAR_8X32
        USE_SCALAR_INV_BUILTIN )
    set_target_properties( secp256k1 PROPERTIES COMPILE_DEFINITIONS "${SECP256K1_BUILD_DEFINES}" LINKER_LANGUAGE C )
else ( WIN32 )
    include(ExternalProject)
    ExternalProject_Add( project_secp256k1
     PREFIX ${CMAKE_CURRENT_BINARY_DIR}/vendor/secp256k1-zkp
     SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/vendor/secp256k1-zkp
     CONFIGURE_COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/vendor/secp256k1-zkp/configure --disable-benchmark --disable-tests --disable-exhaustive-tests --enable-module-recovery --enable-module-rangeproof --enable-module-generator --enable-experimental --with-bignum=no
     BUILD_COMMAND make clean && make
     INSTALL_COMMAND DESTDIR=<INSTALL_DIR> make install
     BUILD_BYPRODUCTS <BINARY_DIR>/.libs/libsecp256k1.a
    )
    ExternalProject_Add_Step(project_secp256k1 autogen
     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/vendor/secp256k1-zkp
     COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/vendor/secp256k1-zkp/autogen.sh
     DEPENDERS configure
    )

    ExternalProject_Get_Property(project_secp256k1 INSTALL_DIR)
    ExternalProject_Get_Property(project_secp256k1 SOURCE_DIR)
#    file(MAKE_DIRECTORY ${INSTALL_DIR}/usr/local/include)
    add_library(secp256k1 STATIC IMPORTED)
    set_target_properties(secp256k1 PROPERTIES
        IMPORTED_LOCATION "${INSTALL_DIR}/usr/local/lib/libsecp256k1.a"
        INTERFACE_INCLUDE_DIRECTORIES "${SOURCE_DIR}/include"
        )

    add_dependencies(secp256k1 project_secp256k1)
endif ( WIN32 )
# End configure secp256k1-zkp

IF( WIN32 )
  MESSAGE(STATUS "Configuring fc to build on Win32")

  set( PLATFORM_SPECIFIC_LIBS WS2_32.lib Userenv.lib crypt32.lib )
  # iphlpapi.lib

ELSE(WIN32)
  MESSAGE(STATUS "Configuring fc to build on Unix/Apple")

ENDIF(WIN32)

IF(NOT "$ENV{OPENSSL_ROOT_DIR}" STREQUAL "")
  set(OPENSSL_ROOT_DIR $ENV{OPENSSL_ROOT_DIR} )
  set(OPENSSL_INCLUDE_DIR ${OPENSSL_ROOT_DIR}/include)
  message(STATUS "Setting up OpenSSL root and include vars to ${OPENSSL_ROOT_DIR}, ${OPENSSL_INCLUDE_DIR}")
ENDIF()

find_package(OpenSSL 1.0 REQUIRED)
message(STATUS "Using OpenSSL ${OPENSSL_VERSION}")

SET(BOOST_COMPONENTS thread filesystem program_options serialization unit_test_framework coroutine iostreams)
SET(Boost_USE_STATIC_LIBS ON CACHE STRING "ON or OFF")

find_package(Boost 1.65.1 REQUIRED COMPONENTS ${BOOST_COMPONENTS})

# We are now building in support for deflate compression into our websockets layer by default,
# which requires zlib.  Aside from that, all of fc compiles without zlib, so this could be
# made optional without much effort
# (important exception, apple: as of 10.10 yosemite, the OpenSSL static libraries shipped with 
# os x have a dependency on zlib)
# On a side note, fc's fc::zlib_compress() function uses a separate implementation of zlib
# from the miniz library.  If we're comfortable requiring an external zlib, we can 
# reimplement fc::zlib_compress() to call the real zlib, and remove miniz.c from our
# repository.
find_package( ZLIB REQUIRED )

set( fc_sources
     src/uint128.cpp
     src/real128.cpp
     src/variant.cpp
     src/exception.cpp
     src/monitoring.cpp
     src/variant_object.cpp
     src/thread/thread.cpp
     src/thread/thread_specific.cpp
     src/thread/future.cpp
     src/thread/task.cpp
     src/thread/spin_lock.cpp
     src/thread/spin_yield_lock.cpp
     src/thread/mutex.cpp
     src/thread/non_preemptable_scope_check.cpp
     src/asio.cpp
     src/string.cpp
     src/shared_ptr.cpp
     src/time.cpp
     src/utf8.cpp
     src/io/iostream.cpp
     src/io/datastream.cpp
     src/io/buffered_iostream.cpp
     src/io/fstream.cpp
     src/io/sstream.cpp
     src/io/json.cpp
     src/io/varint.cpp
     src/io/console.cpp
     src/filesystem.cpp
     src/interprocess/signals.cpp
     src/interprocess/file_mapping.cpp
     src/interprocess/mmap_struct.cpp
     src/rpc/cli.cpp
     src/rpc/http_api.cpp
     src/rpc/json_connection.cpp
     src/rpc/state.cpp
     src/rpc/websocket_api.cpp
     src/log/log_message.cpp
     src/log/logger.cpp
     src/log/appender.cpp
     src/log/console_appender.cpp
     src/log/file_appender.cpp
     src/log/gelf_appender.cpp
     src/log/logger_config.cpp
     src/crypto/_digest_common.cpp
     src/crypto/openssl.cpp
     src/crypto/aes.cpp
     src/crypto/crc.cpp
     src/crypto/city.cpp
     src/crypto/base32.cpp
     src/crypto/base36.cpp
     src/crypto/base58.cpp
     src/crypto/base64.cpp
     src/crypto/bigint.cpp
     src/crypto/hex.cpp
     src/crypto/sha1.cpp
     src/crypto/ripemd160.cpp
     src/crypto/sha256.cpp
     src/crypto/sha224.cpp
     src/crypto/sha512.cpp
     src/crypto/dh.cpp
     src/crypto/blowfish.cpp
     src/crypto/elliptic_common.cpp
     ${ECC_REST}
     src/crypto/elliptic_${ECC_IMPL}.cpp
     src/crypto/rand.cpp
     src/network/tcp_socket.cpp
     src/network/udp_socket.cpp
     src/network/udt_socket.cpp
     src/network/http/http_connection.cpp
     src/network/http/http_server.cpp
     src/network/http/websocket.cpp
     src/network/ntp.cpp
     src/network/ip.cpp
     src/network/rate_limiting.cpp
     src/network/resolve.cpp
     src/network/url.cpp
     src/network/gntp.cpp
     src/compress/smaz.cpp
     src/compress/zlib.cpp
     vendor/cyoencode-1.0.2/src/CyoDecode.c
     vendor/cyoencode-1.0.2/src/CyoEncode.c
     )

file( GLOB_RECURSE fc_headers ${CMAKE_CURRENT_SOURCE_DIR} *.hpp *.h )

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/src/git_revision.cpp.in" "${CMAKE_CURRENT_BINARY_DIR}/git_revision.cpp" @ONLY)
list(APPEND fc_sources "${CMAKE_CURRENT_BINARY_DIR}/git_revision.cpp")
list(APPEND fc_sources ${fc_headers})

add_subdirectory( vendor/websocketpp EXCLUDE_FROM_ALL )
add_subdirectory( vendor/udt4 )

set( UNITY_BUILD OFF )
setup_library( fc SOURCES ${fc_sources} LIBRARY_TYPE STATIC )
install( DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/include/" DESTINATION include )

# begin readline stuff
find_package(Curses)
find_package(Readline)

if (READLINE_FOUND)
  target_compile_definitions (fc PRIVATE HAVE_READLINE)
  set(readline_libraries ${Readline_LIBRARY})
  if (CURSES_FOUND)
    list(APPEND readline_libraries ${CURSES_LIBRARY})
  endif()
  set(readline_includes ${Readline_INCLUDE_DIR})
elseif (NOT WIN32)
  message(FATAL_ERROR "Readline not found")
endif()
# end readline stuff

IF(WIN32)
  target_compile_definitions(fc PRIVATE _CRT_NONSTDC_NO_DEPRECATE _CRT_SECURE_NO_WARNINGS _SCL_SECURE_NO_WARNINGS PUBLIC NOMINMAX
    # The current version of websockets doesn't correctly guess what 'chrono' implementation boost::asio uses
    # on the recommended build platform of VC++12/boost_1.58.  Force it here until websocket gets their
    # autodetecting code to do the right thing.
    _WEBSOCKETPP_CPP11_CHRONO_
  )
ELSE()
  SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")

  IF(APPLE)
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++ -Wall")
  ELSE()
    if( NOT CMAKE_CXX_COMPILER_ID STREQUAL "Clang" )
      target_compile_options(fc PUBLIC -Wall -fnon-call-exceptions)
    endif()
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -fnon-call-exceptions")
  ENDIF()
ENDIF()

# This will become unnecessary once we update to websocketpp which fixes upstream issue #395
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DWEBSOCKETPP_STRICT_MASKING")

SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DBOOST_ASIO_HAS_STD_CHRONO")

target_include_directories(fc
  PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${Boost_INCLUDE_DIR}
    ${OPENSSL_INCLUDE_DIR}
    "${readline_includes}"

  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/vendor/cyoencode-1.0.2/src
    ${CMAKE_CURRENT_SOURCE_DIR}/vendor/udt4/src
    ${CMAKE_CURRENT_SOURCE_DIR}/vendor/websocketpp
    ${CMAKE_CURRENT_SOURCE_DIR}/vendor/secp256k1-zkp
    ${ZLIB_INCLUDE_DIR}
  )

target_link_libraries( fc PUBLIC udt Boost::thread Boost::filesystem Boost::program_options Boost::serialization Boost::coroutine Boost::iostreams Boost::disable_autolinking ${OPENSSL_LIBRARIES} ${ZLIB_LIBRARIES} ${PLATFORM_SPECIFIC_LIBS} ${readline_libraries} ${ECC_LIB} )

if(MSVC)
  set_source_files_properties( src/network/http/websocket.cpp PROPERTIES COMPILE_FLAGS "/bigobj" )
endif(MSVC)

add_executable( api tests/api.cpp )
target_link_libraries( api fc )

if( ECC_IMPL STREQUAL secp256k1 )
    add_executable( blind tests/all_tests.cpp tests/crypto/blind.cpp )
    target_link_libraries( blind fc )
endif()

add_executable( ntp_test tests/all_tests.cpp tests/network/ntp_test.cpp )
target_link_libraries( ntp_test fc )

add_executable( task_cancel_test tests/all_tests.cpp tests/thread/task_cancel.cpp )
target_link_libraries( task_cancel_test fc )


add_executable( bloom_test tests/all_tests.cpp tests/bloom_test.cpp )
target_link_libraries( bloom_test fc )

add_executable( real128_test tests/all_tests.cpp tests/real128_test.cpp )
target_link_libraries( real128_test fc )

add_executable( hmac_test tests/hmac_test.cpp )
target_link_libraries( hmac_test fc )

add_executable( blinding_test tests/blinding_test.cpp )
target_link_libraries( blinding_test fc )


add_executable( udt_server tests/udts.cpp )
target_link_libraries( udt_server fc udt )

add_executable( udt_client tests/udtc.cpp )
target_link_libraries( udt_client fc udt )

add_executable( ecc_test tests/crypto/ecc_test.cpp )
target_link_libraries( ecc_test fc )

#add_executable( test_aes tests/aes_test.cpp )
#target_link_libraries( test_aes fc )
#add_executable( test_sleep tests/sleep.cpp )
#target_link_libraries( test_sleep fc )
#add_executable( test_rate_limiting tests/rate_limiting.cpp )
#target_link_libraries( test_rate_limiting fc )

add_executable( all_tests tests/all_tests.cpp
                          tests/compress/compress.cpp
                          tests/crypto/aes_test.cpp
                          tests/crypto/base_n_tests.cpp
                          tests/crypto/bigint_test.cpp
                          tests/crypto/blind.cpp
                          tests/crypto/blowfish_test.cpp
                          tests/crypto/dh_test.cpp
                          tests/crypto/rand_test.cpp
                          tests/crypto/sha_tests.cpp
                          tests/network/ntp_test.cpp
                          tests/network/http/websocket_test.cpp
                          tests/thread/task_cancel.cpp
                          tests/bloom_test.cpp
                          tests/real128_test.cpp
                          tests/utf8_test.cpp
                          )
target_link_libraries( all_tests fc )

MESSAGE(STATUS "Finished fc module configuration...")
