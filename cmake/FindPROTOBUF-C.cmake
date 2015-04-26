#------------------------------------------------------------------------------
#
#  Copyright (C) 2010  Artem Rodygin
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#------------------------------------------------------------------------------
#
#  This module finds if C API of PROTOBUF library is installed and determines where required
#  include files and libraries are. The module sets the following variables:
#
#    PROTOBUF_FOUND         - system has PROTOBUF
#    PROTOBUF_INCLUDE_DIR   - the PROTOBUF include directory
#    PROTOBUF_LIBRARIES     - the libraries needed to use PROTOBUF
#    PROTOBUF_DEFINITIONS   - the compiler definitions, required for building with PROTOBUF
#    PROTOBUF_VERSION_MAJOR - the major version of the PROTOBUF release
#    PROTOBUF_VERSION_MINOR - the minor version of the PROTOBUF release
#
#  You can help the module to find PROTOBUF by specifying its root path
#  in environment variable named "PROTOBUF_ROOTDIR". If this variable is not set
#  then module will search for files in "/usr/local" and "/usr" by default.
#
#------------------------------------------------------------------------------

set(PROTOBUF_FOUND TRUE)

# search for header

find_path(PROTOBUF_INCLUDE_DIR
          NAMES "google/protobuf-c/protobuf-c.h"
          PATHS "/usr/local"
                "/usr"
                ENV PROTOBUF_ROOTDIR
          PATH_SUFFIXES "include")

# header is found

if (PROTOBUF_INCLUDE_DIR)

    set(PROTOBUF_INCLUDE_DIR "${PROTOBUF_INCLUDE_DIR}/google/protobuf-c")

    # search for library

    find_library(PROTOBUF_LIBRARIES
                 NAMES "libprotobuf-c.so"
                 PATHS "/usr/local"
                       "/usr"
                 ENV PROTOBUF_ROOTDIR
                 PATH_SUFFIXES "lib")

endif (PROTOBUF_INCLUDE_DIR)

# header is not found

if (NOT PROTOBUF_INCLUDE_DIR)
    set(PROTOBUF_FOUND FALSE)
endif (NOT PROTOBUF_INCLUDE_DIR)

# library is not found

if (NOT PROTOBUF_LIBRARIES)
    set(PROTOBUF_FOUND FALSE)
endif (NOT PROTOBUF_LIBRARIES)

set(PROTOBUF_ERROR_MESSAGE "Unable to find PROTOBUF library")

if (NOT PROTOBUF_FOUND)
    set(PROTOBUF_ERROR_MESSAGE "Unable to find PROTOBUF library v${PROTOBUF_FIND_VERSION} (${PROTOBUF_FOUND_VERSION} was found)")
endif (NOT PROTOBUF_FOUND)

# add definitions

if (PROTOBUF_FOUND)

    if (CMAKE_SYSTEM_PROCESSOR MATCHES ia64)
        set(PROTOBUF_DEFINITIONS "-D_REENTRANT -D_FILE_OFFSET_BITS=64")
    elseif (CMAKE_SYSTEM_PROCESSOR MATCHES amd64)
        set(PROTOBUF_DEFINITIONS "-D_REENTRANT -D_FILE_OFFSET_BITS=64")
    elseif (CMAKE_SYSTEM_PROCESSOR MATCHES x86_64)
        set(PROTOBUF_DEFINITIONS "-D_REENTRANT -D_FILE_OFFSET_BITS=64")
    else (CMAKE_SYSTEM_PROCESSOR MATCHES ia64)
        set(PROTOBUF_DEFINITIONS "-D_REENTRANT")
    endif (CMAKE_SYSTEM_PROCESSOR MATCHES ia64)

endif (PROTOBUF_FOUND)

# final status messages

if (PROTOBUF_FOUND)

    if (NOT PROTOBUF_FIND_QUIETLY)
        message(STATUS "PROTOBUF-C")
    endif (NOT PROTOBUF_FIND_QUIETLY)

    mark_as_advanced(PROTOBUF_INCLUDE_DIR
                     PROTOBUF_LIBRARIES
                     PROTOBUF_DEFINITIONS)

else (PROTOBUF_FOUND)

    if (PROTOBUF_FIND_REQUIRED)
        message(SEND_ERROR "${PROTOBUF_ERROR_MESSAGE}")
    endif (PROTOBUF_FIND_REQUIRED)

endif (PROTOBUF_FOUND)
