include(FetchContent)

# ---- libcurl ---------------------------------------------------------------
# Prefer a system libcurl on Linux so distro TLS/CA integration stays native.
# Windows keeps a pinned static libcurl build with Schannel for a portable app.
if(WIN32)
  # curl uses the generic BUILD_TESTING cache option. Preserve NativeDNS'
  # setting so disabling curl's tests does not accidentally disable our CTest
  # suite as well.
  set(NATIVEDNS_SAVED_BUILD_TESTING "${BUILD_TESTING}")
  set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
  set(BUILD_STATIC_LIBS ON CACHE BOOL "" FORCE)
  set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
  set(ENABLE_LIB_ONLY ON CACHE BOOL "" FORCE)
  set(ENABLE_DOC OFF CACHE BOOL "" FORCE)
  set(ENABLE_STATIC_CRT OFF CACHE BOOL "" FORCE)
  FetchContent_Declare(nghttp2
    URL https://github.com/nghttp2/nghttp2/releases/download/v1.70.0/nghttp2-1.70.0.tar.xz
    URL_HASH SHA256=e05cb1388eaca3830aded4ccf20044b6e1ac1a61411dcca11b0437c4285c8bc2
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
  FetchContent_MakeAvailable(nghttp2)
  if(MSVC)
    target_compile_options(nghttp2_static PRIVATE /WX- /wd4201 /wd4244)
  endif()
  set(NGHTTP2_INCLUDE_DIR "${nghttp2_SOURCE_DIR}/lib/includes" CACHE PATH "" FORCE)
  set(NGHTTP2_LIBRARY nghttp2_static CACHE STRING "" FORCE)
  set(NGHTTP2_USE_STATIC_LIBS ON CACHE BOOL "" FORCE)
  set(BUILD_CURL_EXE OFF CACHE BOOL "" FORCE)
  set(BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
  set(BUILD_LIBCURL_DOCS OFF CACHE BOOL "" FORCE)
  set(BUILD_MISC_DOCS OFF CACHE BOOL "" FORCE)
  set(ENABLE_CURL_MANUAL OFF CACHE BOOL "" FORCE)
  set(CURL_DISABLE_INSTALL ON CACHE BOOL "" FORCE)
  set(CURL_STATIC_CRT OFF CACHE BOOL "" FORCE)
  set(CURL_USE_SCHANNEL ON CACHE BOOL "" FORCE)
  set(CURL_USE_OPENSSL OFF CACHE BOOL "" FORCE)
  set(CURL_USE_LIBPSL OFF CACHE BOOL "" FORCE)
  set(CURL_USE_LIBSSH2 OFF CACHE BOOL "" FORCE)
  set(USE_LIBIDN2 OFF CACHE BOOL "" FORCE)
  set(USE_WIN32_IDN OFF CACHE BOOL "" FORCE)
  set(CURL_ZLIB OFF CACHE STRING "" FORCE)
  set(CURL_BROTLI OFF CACHE STRING "" FORCE)
  set(CURL_ZSTD OFF CACHE STRING "" FORCE)
  set(USE_NGHTTP2 ON CACHE BOOL "" FORCE)
  set(HTTP_ONLY ON CACHE BOOL "" FORCE)
  set(CURL_DISABLE_COOKIES ON CACHE BOOL "" FORCE)
  set(CURL_DISABLE_NETRC ON CACHE BOOL "" FORCE)
  set(CURL_DISABLE_PROXY ON CACHE BOOL "" FORCE)
  set(CURL_DISABLE_HTTP_AUTH ON CACHE BOOL "" FORCE)
  set(CURL_DISABLE_ALTSVC ON CACHE BOOL "" FORCE)
  set(CURL_DISABLE_HSTS ON CACHE BOOL "" FORCE)
  FetchContent_Declare(curl
    URL https://curl.se/download/curl-8.22.0.tar.xz
    URL_HASH SHA256=f7ef3ae8a22e521f289803fe93543eb64c329b58aa73a9e224dfd915a2a5f4f7
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
  FetchContent_MakeAvailable(curl)
  set(BUILD_TESTING "${NATIVEDNS_SAVED_BUILD_TESTING}" CACHE BOOL "Build NativeDNS tests" FORCE)
  unset(NATIVEDNS_SAVED_BUILD_TESTING)
else()
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(LIBCURL REQUIRED IMPORTED_TARGET libcurl)
  add_library(NativeDNS.Curl INTERFACE)
  target_link_libraries(NativeDNS.Curl INTERFACE PkgConfig::LIBCURL)
  add_library(CURL::libcurl ALIAS NativeDNS.Curl)
endif()

# ---- libsodium -------------------------------------------------------------
if(WIN32)
  FetchContent_Declare(sodium
    URL https://github.com/jedisct1/libsodium/releases/download/1.0.22-RELEASE/libsodium-1.0.22-msvc.zip
    URL_HASH SHA256=3e03a726fac4bc09cb61d8f29d658ef7a5eca0811de59082130414f7ca2e4279
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    SOURCE_SUBDIR cmake-unused)
  FetchContent_MakeAvailable(sodium)
  # The prebuilt "static" libsodium package is compiled with /MT[d].
  # Linking that into Qt (/MD[d]) caused LNK4098 and cross-CRT heap hazards.
  # Use the official dynamic v143 build instead.
  add_library(Sodium.Shared SHARED IMPORTED GLOBAL)
  set_target_properties(Sodium.Shared PROPERTIES
    IMPORTED_IMPLIB_DEBUG "${sodium_SOURCE_DIR}/x64/Debug/v143/dynamic/libsodium.lib"
    IMPORTED_LOCATION_DEBUG "${sodium_SOURCE_DIR}/x64/Debug/v143/dynamic/libsodium.dll"
    IMPORTED_IMPLIB_RELEASE "${sodium_SOURCE_DIR}/x64/Release/v143/dynamic/libsodium.lib"
    IMPORTED_LOCATION_RELEASE "${sodium_SOURCE_DIR}/x64/Release/v143/dynamic/libsodium.dll"
    IMPORTED_IMPLIB_RELWITHDEBINFO "${sodium_SOURCE_DIR}/x64/Release/v143/dynamic/libsodium.lib"
    IMPORTED_LOCATION_RELWITHDEBINFO "${sodium_SOURCE_DIR}/x64/Release/v143/dynamic/libsodium.dll"
    IMPORTED_IMPLIB_MINSIZEREL "${sodium_SOURCE_DIR}/x64/Release/v143/dynamic/libsodium.lib"
    IMPORTED_LOCATION_MINSIZEREL "${sodium_SOURCE_DIR}/x64/Release/v143/dynamic/libsodium.dll"
    INTERFACE_INCLUDE_DIRECTORIES "${sodium_SOURCE_DIR}/include")
  add_library(Sodium::sodium ALIAS Sodium.Shared)

  function(nativedns_copy_sodium_runtime target)
    add_custom_command(TARGET ${target} POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "$<TARGET_FILE:Sodium.Shared>" "$<TARGET_FILE_DIR:${target}>")
  endfunction()
else()
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)
  add_library(NativeDNS.Sodium INTERFACE)
  target_link_libraries(NativeDNS.Sodium INTERFACE PkgConfig::SODIUM)
  add_library(Sodium::sodium ALIAS NativeDNS.Sodium)
endif()

# ---- WinDivert -------------------------------------------------------------
if(WIN32)
  FetchContent_Declare(windivert
    URL https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip
    URL_HASH SHA256=63cb41763bb4b20f600b6de04e991a9c2be73279e317d4d82f237b150c5f3f15
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
  FetchContent_MakeAvailable(windivert)
  set(NATIVEDNS_WINDIVERT_ROOT "${windivert_SOURCE_DIR}" CACHE INTERNAL "Pinned WinDivert SDK root" FORCE)
  add_library(WinDivert.Headers INTERFACE)
  target_include_directories(WinDivert.Headers INTERFACE "${NATIVEDNS_WINDIVERT_ROOT}/include")

  function(nativedns_copy_windivert_runtime target)
    add_custom_command(TARGET ${target} POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E copy_if_different "${NATIVEDNS_WINDIVERT_ROOT}/x64/WinDivert.dll" "$<TARGET_FILE_DIR:${target}>"
      COMMAND ${CMAKE_COMMAND} -E copy_if_different "${NATIVEDNS_WINDIVERT_ROOT}/x64/WinDivert64.sys" "$<TARGET_FILE_DIR:${target}>"
      COMMAND ${CMAKE_COMMAND} -E copy_if_different "${NATIVEDNS_WINDIVERT_ROOT}/LICENSE" "$<TARGET_FILE_DIR:${target}>/WinDivert-LICENSE.txt")
  endfunction()
endif()
