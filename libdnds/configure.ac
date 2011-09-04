#
# Autoconf requirements
#

AC_PREREQ([2.67])
AC_INIT([DNDS library],[0.1],[nicboul@gmail.com],[libdnds],[https://github.com/nicboul/DNDS/wiki])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
LT_PREREQ([2.2])
LT_INIT([dlopen])

AC_CONFIG_SRCDIR([src/krypt.c])
AC_CONFIG_HEADERS(config.h)

CFLAGS=-g
CXXFLAGS=-g

# Checks for programs
AC_PROG_CC
AC_PROG_CXX

# Checks for libraries
## UDT
AC_ARG_WITH(udt,
	AS_HELP_STRING([--with-udt=PATH],
		[Path for UDT library and headers]
	),
)

if test "x{$with_udt}" != "x"; then

	AC_SUBST(UDT_PATH, $with_udt)
	AC_SUBST(WANT_UDT, udtbus.lo)

	# precious vars
	AC_ARG_VAR(UDT_CXXFLAGS, [CPP compiler flags for UDT])
	AC_ARG_VAR(UDT_LIBS, [linker flags for UDT])
	
	# vars will be used into makefiles
	AC_SUBST([UDT_CXXFLAGS], ["-I$with_udt"])
	AC_SUBST([UDT_LIBS], ["-L$with_udt -lstdc++ -lpthread -lm"])

	AC_DEFINE(HAVE_UDT, [1], [Define if you have libudt])
fi

## OpenSSL
PKG_CHECK_MODULES([openssl], [openssl >= 0.9.8j], [have_openssl=yes], [have_openssl=no])

## tuntap driver
AC_CHECK_HEADER(linux/if_tun.h, [AC_SUBST(TUN_FLAVOR, tun_ifreq.lo)])
AC_CHECK_HEADER(net/if_tun.h, [AC_SUBST(TUN_FLAVOR, tun_tuninfo.lo)])

## epoll/kqueue
AC_CHECK_FUNC(kqueue, [AC_SUBST(ION_FLAVOR, ion_kqueue.lo)])
AC_CHECK_FUNC(epoll_ctl, [AC_SUBST(ION_FLAVOR, ion_epoll.lo)])

AC_CONFIG_FILES([Makefile
		 src/Makefile
		 src/asn1/Makefile
		 config/libdnds.pc])
AC_OUTPUT


# check for the system that will run the software
#AC_CANONICAL_HOST()


#
# checks for libraries
#

# openssl
AC_ARG_WITH(openssl-prefix,
		AS_HELP_STRING([--with-openssl-prefix=PREFIX],
			[Prefix where openssl is installed (optional)]
		)
)

# precious vars
AC_ARG_VAR(openssl_CFLAGS, [compiler flags for OpenSSL])
AC_ARG_VAR(openssl_LIBS, [linker flags for OpenSSL])

#CFLAGS_save=$CFLAGS
#LIBS_save=$LIBS

# check with openssl-prefix
if test "x$with_openssl_prefix" = "x"; then
	with_openssl_prefix="/usr"
fi

# TODO - should we prefix $LIBS and $CLFAGS here?
LIBS="$LIBS -L$with_openssl_prefix/lib"
CFLAGS="$CFLAGS -I$with_openssl_prefix/include"

# check with pkg-config, if with_openssl_prefix isn't specified
if test "x$have_openssl" != "xyes" && test "x$with_openssl_prefix" = "x/usr"; then
	PKG_CHECK_EXISTS([openssl], [pkgconfig_have_openssl=yes], [pkgconfig_have_openssl=no])
	if test "x$pkgconfig_have_openssl" = "xyes"; then
		PKG_CHECK_MODULES([openssl], [openssl >= 0.9.8j], [have_openssl=yes], [have_openssl=no])
	fi
fi

# check for system library (mainly for openbsd)
if test "x$have_openssl" != "xyes"; then
	AC_CHECK_HEADER([openssl/crypto.h], [header_have_crypto=yes], [header_have_crypto=no])
	AC_CHECK_LIB([crypto], [main], [lib_have_crypto=yes], [lib_have_crypto=no])

	if test "x$lib_have_crypto" = "xyes" && test "x$header_have_crypto" = "xyes"; then
		AC_CHECK_HEADER([openssl/ssl.h], [header_have_ssl=yes], [header_have_ssl=no])
		AC_CHECK_LIB([ssl], [SSL_library_init], [lib_have_ssl=yes], [lib_have_ssl=no], [-lcrypto])

		if test "x$lib_have_ssl" = "xyes" && test "x$header_have_ssl" = "xyes"; then
			have_openssl=yes
			openssl_LIBS="-L$with_openssl_prefix/lib -lcrypto -lssl"
			openssl_CFLAGS="-I$with_openssl_prefix/include"
		fi
	fi
fi

AC_SUBST([openssl_CFLAGS]) 
AC_SUBST([openssl_LIBS]) 

CFLAGS=$CFLAGS_save
LIBS=$LIBS_save

# error
if test "x$have_openssl" != "xyes"; then
	AC_MSG_ERROR([Unable to find openssl in your system])
fi

#
## dlopen
AC_SEARCH_LIBS(dlopen, dl)
#
## ...
#
##
# checks for header files
#

# std config.h
AC_HEADER_STDC

# tun
AC_CHECK_HEADER(linux/if_tun.h, [AC_SUBST(TUN_FLAVOR, tun_ifreq.lo)])
AC_CHECK_HEADER(net/if_tun.h, [AC_SUBST(TUN_FLAVOR, tun_tuninfo.lo)])

#
# checks for types
#

#
# checks for structures
#

#
# checks for compiler characteristics
#
AC_C_CONST
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_STRUCT_TM
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

#
# checks for library functions
#

# ion
AC_CHECK_FUNC(kqueue, [AC_SUBST(ION_FLAVOR, ion_kqueue.lo)])
AC_CHECK_FUNC(epoll_ctl, [AC_SUBST(ION_FLAVOR, ion_epoll.lo)])

#
# checks for system services
#

#
# Final
#
