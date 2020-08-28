# - Try to find etebase
# Once done this will define
#  ETEBASE_FOUND - System has etebase
#  ETEBASE_INCLUDE_DIRS - The etebase include directories
#  ETEBASE_LIBRARIES - The libraries needed to use etebase
#  ETEBASE_DEFINITIONS - Compiler switches required for using etebase

find_package(PkgConfig)
if ("${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION}.${CMAKE_PATCH_VERSION}" VERSION_GREATER "2.8.1")
   # "QUIET" was introduced in 2.8.2
   set(_QUIET QUIET)
endif ()
pkg_check_modules(PC_ETEBASE ${_QUIET} etebase)

find_library(ETEBASE_LIBRARY
             NAMES ${PC_ETEBASE_LIBRARIES}
             HINTS ${PC_ETEBASE_LIBDIR} ${PC_ETEBASE_LIBRARY_DIRS} )

set(ETEBASE_DEFINITIONS ${PC_ETEBASE_CFLAGS_OTHER})
set(ETEBASE_LIBRARIES ${ETEBASE_LIBRARY})
set(ETEBASE_INCLUDE_DIRS ${PC_ETEBASE_INCLUDE_DIRS})

include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set ETEBASE_FOUND to TRUE
# if all listed variables are TRUE
find_package_handle_standard_args(Etebase DEFAULT_MSG
   ETEBASE_LIBRARIES ETEBASE_INCLUDE_DIRS)

mark_as_advanced(ETEBASE_INCLUDE_DIRS ETEBASE_LIBRARY ETEBASE_LIBRARIES ETEBASE_DEFINITIONS)
