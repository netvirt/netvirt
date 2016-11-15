# - Try to find LibreSSL include dirs and libraries
#
# Usage of this module as follows:
#
#     find_package(LibreSSL)
#
# Variables used by this module, they can change the default behaviour and need
# to be set before calling find_package:
#
#  LibreSSL_ROOT_DIR          Set this variable to the root installation of
#                            LibreSSL if the module has problems finding the
#                            proper installation path.
#
# Variables defined by this module:
#
#  LIBRESSL_FOUND             System has LibreSSL, include and library dirs found
#  LIBRESSL_INCLUDE_DIR       The LibreSSL include directories.
#  LIBRESSL_LIBRARIES         The LibreSSL libraries.
#  LIBRESSL_CYRPTO_LIBRARY    The LibreSSL crypto library.
#  LIBRESSL_SSL_LIBRARY       The LibreSSL ssl library.

find_path(LibreSSL_ROOT_DIR
        NAMES include/openssl/ssl.h
        )

find_path(LibreSSL_INCLUDE_DIR
        NAMES openssl/ssl.h
        HINTS ${LibreSSL_ROOT_DIR}/include
        )

find_library(LibreSSL_SSL_LIBRARY
        NAMES libssl-39
        HINTS ${LibreSSL_ROOT_DIR}/x86
        )

find_library(LibreSSL_CRYPTO_LIBRARY
        NAMES libcrypto-38
        HINTS ${LibreSSL_ROOT_DIR}/x86
        )

set(LibreSSL_LIBRARIES ${LibreSSL_SSL_LIBRARY} ${LibreSSL_CRYPTO_LIBRARY}
        CACHE STRING "LibreSSL SSL and crypto libraries" FORCE)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LibreSSL DEFAULT_MSG
        LibreSSL_LIBRARIES
        LibreSSL_INCLUDE_DIR
        )

mark_as_advanced(
        LibreSSL_ROOT_DIR
        LibreSSL_INCLUDE_DIR
        LibreSSL_LIBRARIES
        LibreSSL_CRYPTO_LIBRARY
        LibreSSL_SSL_LIBRARY
)
