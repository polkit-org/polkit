dnl Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59c)
AC_INIT(polkit, 0.104, http://lists.freedesktop.org/mailman/listinfo/polkit-devel)
AM_INIT_AUTOMAKE(polkit, 0.104)
AM_CONFIG_HEADER(config.h)
AM_MAINTAINER_MODE

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

# Include external mocklibc tool for unit testing
AC_CONFIG_SUBDIRS([test/mocklibc])

# libtool versioning - this applies to all libraries in this package
#
# See http://sources.redhat.com/autobook/autobook/autobook_91.html#SEC91 for details
#
LT_CURRENT=0
LT_REVISION=0
LT_AGE=0
AC_SUBST(LT_CURRENT)
AC_SUBST(LT_REVISION)
AC_SUBST(LT_AGE)

AC_ISC_POSIX
AC_PROG_CC
AM_PROG_CC_STDC
AC_HEADER_STDC
AM_PROG_LIBTOOL
AC_PROG_MAKE_SET
AC_PROG_LN_S
AC_SYS_LARGEFILE
AM_PROG_CC_C_O

# Taken from dbus
AC_ARG_ENABLE(ansi,             [  --enable-ansi           enable -ansi -pedantic gcc flags],enable_ansi=$enableval,enable_ansi=no)
AC_ARG_ENABLE(verbose-mode,     [  --enable-verbose-mode   support verbose debug mode],enable_verbose_mode=$enableval,enable_verbose_mode=$USE_MAINTAINER_MODE)
AC_ARG_ENABLE(man-pages,        [  --enable-man-pages      build manual pages],enable_man_pages=$enableval,enable_man_pages=yes)

if test "${enable_man_page}" != no; then
dnl
dnl Check for xsltproc
dnl
AC_PATH_PROG([XSLTPROC], [xsltproc])
  if test -z "$XSLTPROC"; then
    enable_man_pages=no
  fi
fi
AM_CONDITIONAL(MAN_PAGES_ENABLED, test x$enable_man_pages = xyes)

GTK_DOC_CHECK([1.3])

#### gcc warning flags

if test "x$GCC" = "xyes"; then
  changequote(,)dnl
  case " $CFLAGS " in
  *[\ \	]-Wall[\ \	]*) ;;
  *) CFLAGS="$CFLAGS -Wall" ;;
  esac

  case " $CFLAGS " in
  *[\ \	]-Wchar-subscripts[\ \	]*) ;;
  *) CFLAGS="$CFLAGS -Wchar-subscripts" ;;
  esac

  case " $CFLAGS " in
  *[\ \	]-Wmissing-declarations[\ \	]*) ;;
  *) CFLAGS="$CFLAGS -Wmissing-declarations" ;;
  esac

  case " $CFLAGS " in
  *[\ \	]-Wnested-externs[\ \	]*) ;;
  *) CFLAGS="$CFLAGS -Wnested-externs" ;;
  esac

  case " $CFLAGS " in
  *[\ \	]-Wpointer-arith[\ \	]*) ;;
  *) CFLAGS="$CFLAGS -Wpointer-arith" ;;
  esac

  case " $CFLAGS " in
  *[\ \	]-Wcast-align[\ \	]*) ;;
  *) CFLAGS="$CFLAGS -Wcast-align" ;;
  esac

  case " $CFLAGS " in
  *[\ \	]-Wsign-compare[\ \	]*) ;;
  *) CFLAGS="$CFLAGS -Wsign-compare" ;;
  esac

  case " $CFLAGS " in
  *[\ \	]-Wformat[\ \	]*) ;;
  *) CFLAGS="$CFLAGS -Wformat" ;;
  esac

  case " $CFLAGS " in
  *[\ \	]-Wformat-security[\ \	]*) ;;
  *) CFLAGS="$CFLAGS -Wformat-security" ;;
  esac

  if test "x$enable_ansi" = "xyes"; then
    case " $CFLAGS " in
    *[\ \	]-ansi[\ \	]*) ;;
    *) CFLAGS="$CFLAGS -ansi" ;;
    esac

    case " $CFLAGS " in
    *[\ \	]-D_POSIX_C_SOURCE*) ;;
    *) CFLAGS="$CFLAGS -D_POSIX_C_SOURCE=199309L" ;;
    esac

    case " $CFLAGS " in
    *[\ \	]-D_BSD_SOURCE[\ \	]*) ;;
    *) CFLAGS="$CFLAGS -D_BSD_SOURCE" ;;
    esac

    case " $CFLAGS " in
    *[\ \	]-pedantic[\ \	]*) ;;
    *) CFLAGS="$CFLAGS -pedantic" ;;
    esac
  fi
  changequote([,])dnl
fi

PKG_CHECK_MODULES(GLIB, [gio-2.0 >= 2.28.0])
AC_SUBST(GLIB_CFLAGS)
AC_SUBST(GLIB_LIBS)

EXPAT_LIB=""
AC_ARG_WITH(expat, [  --with-expat=<dir>      Use expat from here],
                      [
                      expat=$withval
                      CPPFLAGS="$CPPFLAGS -I$withval/include"
                      LDFLAGS="$LDFLAGS -L$withval/lib"
                      ]
                      )
AC_CHECK_HEADERS(expat.h, [AC_DEFINE(HAVE_EXPAT_H)], 
		 [AC_MSG_ERROR([Can't find expat.h. Please install expat.])])
AC_CHECK_LIB(expat,XML_ParserCreate,[EXPAT_LIBS="-lexpat"],
	     [AC_MSG_ERROR([Can't find expat library. Please install expat.])])
AC_SUBST(EXPAT_LIBS)

AC_CHECK_FUNCS(clearenv)

if test "x$GCC" = "xyes"; then
  LDFLAGS="-Wl,--as-needed $LDFLAGS"
fi

dnl ---------------------------------------------------------------------------
dnl - Select wether to use systemd or ConsoleKit for session tracking
dnl ---------------------------------------------------------------------------

AC_ARG_ENABLE([systemd],
              AS_HELP_STRING([--enable-systemd], [Use systemd]),
              [with_systemd=$enableval],
              [with_systemd=no])
if test "$with_systemd" = "yes" ; then
  PKG_CHECK_MODULES(SYSTEMD, [libsystemd-login])
  SESSION_TRACKING=systemd
else
  SESSION_TRACKING=ConsoleKit
fi

AC_SUBST(SYSTEMD_CFLAGS)
AC_SUBST(SYSTEMD_LIBS)

AM_CONDITIONAL(HAVE_SYSTEMD, [test "$with_systemd" = "yes"], [Using systemd])

dnl ---------------------------------------------------------------------------
dnl - Select which authentication framework to use
dnl ---------------------------------------------------------------------------

AC_ARG_WITH([authfw],
	    AS_HELP_STRING([--with-authfw=<name>], 
                           [Authentication framework (none/pam/shadow)]))
if ! test -z "$with_authfw" ; then
  if test x$with_authdb = xdummy ; then
    if ! test x$with_authfw = xnone ; then
      AC_MSG_ERROR([Only 'none' is a valid authentication framework for the dummy authorization database])
    fi
  else
      if test x$with_authfw = xnone ; then
        AC_MSG_ERROR(['none' is only a valid authentication framework for the dummy authorization database])
      fi
  fi
  POLKIT_AUTHFW=$with_authfw
else
  if test x$with_authdb = xdummy ; then
    POLKIT_AUTHFW=none
  else
    POLKIT_AUTHFW=pam
  fi
fi

AC_SUBST(POLKIT_AUTHFW)
AC_DEFINE_UNQUOTED(POLKIT_AUTHFW,"$POLKIT_AUTHFW", [Authentication Framework to use])

case $POLKIT_AUTHFW in
  none)
    need_pam=no
    AC_DEFINE(POLKIT_AUTHFW_NONE, 1, [If using no authentication framework])
    ;;

  pam)
    need_pam=yes
    AC_DEFINE(POLKIT_AUTHFW_PAM, 1, [If using the PAM authentication framework])
    ;;

  shadow)
    need_pam=no
    AUTH_LIBS="${AUTH_LIBS} -lcrypt"
    AC_DEFINE(POLKIT_AUTHFW_SHADOW, 1, [If using the Shadow authentication framework])
    ;;

  *)
    AC_MSG_ERROR([Unknown Authentication Framework: $POLKIT_AUTHFW])
    ;;
esac

AM_CONDITIONAL(POLKIT_AUTHFW_NONE, [test x$POLKIT_AUTHFW = xnone], [Using no authfw])
AM_CONDITIONAL(POLKIT_AUTHFW_PAM, [test x$POLKIT_AUTHFW = xpam], [Using PAM authfw])
AM_CONDITIONAL(POLKIT_AUTHFW_SHADOW, [test x$POLKIT_AUTHFW = xshadow], [Using Shadow authfw])


dnl ---------------------------------------------------------------------------
dnl - Check for PAM
dnl ---------------------------------------------------------------------------

withval=""
AC_ARG_WITH(pam-prefix,
[  --with-pam-prefix=<prefix> specify where pam files go],[
if test x$withval != x; then
   AC_MSG_RESULT("PAM files will be installed in prefix ${withval}.")
fi])
if test x$withval != x; then
	PAM_PREFIX_UNEXPANDED="$withval"
else
	PAM_PREFIX_UNEXPANDED="$sysconfdir"
fi
PAM_PREFIX=`eval echo $PAM_PREFIX_UNEXPANDED`
AC_SUBST(PAM_PREFIX)

have_pam=no
if test "$need_pam" = yes ; then
  AC_CHECK_LIB(pam, pam_start, have_pam=yes)
fi

if test x$have_pam = xno; then
    if test "$need_pam" = yes ; then
      AC_ERROR([Could not find pam/pam-devel, please install the needed packages.])
    fi
else
    AUTH_LIBS="${AUTH_LIBS} -lpam"
    AC_DEFINE(HAVE_PAM, 1, [Define if PAM support is included])

    # On Linux, sigtimedwait() is in libc; on Solaris, it's in librt.
    have_timedwait=no
    AC_CHECK_LIB(c, sigtimedwait, [have_timedwait=yes])
    if test "$have_timedwait" = no ; then
      AC_CHECK_LIB(rt, sigtimedwait, [AUTH_LIBS="${AUTH_LIBS} -lrt"])
    fi

    AC_MSG_CHECKING(how to call pam_strerror)
    AC_CACHE_VAL(ac_cv_pam_strerror_args,
     [AC_TRY_COMPILE([#include <stdio.h>
                      #include <stdlib.h>
                      #include <security/pam_appl.h>],
                     [pam_handle_t *pamh = 0;
                      char *s = pam_strerror(pamh, PAM_SUCCESS);],
                     [ac_pam_strerror_args=2],
                     [AC_TRY_COMPILE([#include <stdio.h>
                                      #include <stdlib.h>
                                      #include <security/pam_appl.h>],
                                     [char *s =
                                       pam_strerror(PAM_SUCCESS);],
                                     [ac_pam_strerror_args=1],
                                     [ac_pam_strerror_args=0])])
      ac_cv_pam_strerror_args=$ac_pam_strerror_args])
    ac_pam_strerror_args=$ac_cv_pam_strerror_args
    if test "$ac_pam_strerror_args" = 1 ; then
      AC_MSG_RESULT(one argument)
    elif test "$ac_pam_strerror_args" = 2 ; then
      AC_DEFINE(PAM_STRERROR_TWO_ARGS, 1, [Define if pam_strerror takes two arguments])
      AC_MSG_RESULT(two arguments)
    else
      AC_MSG_RESULT(unknown)
    fi
 
fi

AM_CONDITIONAL(HAVE_PAM, test x$have_pam = xyes)
AC_SUBST(HAVE_PAM)
AC_SUBST(AUTH_LIBS)

AC_CHECK_HEADER(security/pam_modutil.h, [AC_DEFINE(HAVE_PAM_MODUTIL_H, [], "Have pam_modutil.h")])
AC_CHECK_HEADER(security/pam_ext.h, [AC_DEFINE(HAVE_PAM_EXT_H, [], "Have pam_ext.h")])
AC_CHECK_LIB(pam, pam_vsyslog, [AC_DEFINE(HAVE_PAM_VSYSLOG, [], "Have pam_vsyslog")])

AC_ARG_WITH(pam-module-dir, [  --with-pam-module-dir=[dirname]  directory to install PAM security module])
if ! test -z "$with_pam_module_dir"; then
    PAM_MODULE_DIR=$with_pam_module_dir
else
    PAM_MODULE_DIR="/lib/security"
fi

AC_SUBST(PAM_MODULE_DIR)

AC_ARG_WITH(os-type,     [  --with-os-type=<os>        distribution or OS (redhat/suse/gentoo/pardus/solaris)])

#### Check our operating system (distro-tweaks required)
if test "z$with_os_type" = "z"; then
	AC_CHECK_FILE(/etc/redhat-release,distro_type="redhat")
	AC_CHECK_FILE(/etc/SuSE-release,distro_type="suse")
	AC_CHECK_FILE(/etc/gentoo-release,distro_type="gentoo")
	AC_CHECK_FILE(/etc/pardus-release,distro_type="pardus")
	if test "z$distro_type" = "z"; then
		echo "Linux distribution autodetection failed, specify the distribution to target using --with-os-type="
	else
		operating_system=`echo ${distro_type} | tr '[[:upper:]]' '[[:lower:]]' `
	fi
fi

#### Sort out OS (distro-tweaks required)
if test x$with_os_type = x; then
    if test x$operating_system = xredhat ; then
        with_os_type=redhat
    elif test x$operating_system = xsuse ; then
        with_os_type=suse
    elif test x$operating_system = xgentoo ; then
        with_os_type=gentoo
    elif test x$operating_system = xpardus ; then
        with_os_type=pardus
    elif test x$operating_system = xsolaris ; then
	with_os_type=solaris
    elif test x$operating_system = xfreebsd ; then
	with_os_type=freebsd
    else
        with_os_type=unknown
    fi
fi

# (distro-tweaks required)
AM_CONDITIONAL(OS_TYPE_UNKNOWN, test x$with_os_type = xunknown, [Running on unknown OS])
AM_CONDITIONAL(OS_TYPE_RED_HAT, test x$with_os_type = xredhat, [Running on Red Hat OS'es])
AM_CONDITIONAL(OS_TYPE_SUSE, test x$with_os_type = xsuse, [Running on SUSE OS'es])
AM_CONDITIONAL(OS_TYPE_GENTOO, test x$with_os_type = xgentoo, [Running on Gentoo OS'es])
AM_CONDITIONAL(OS_TYPE_PARDUS, test x$with_os_type = xpardus, [Running on Pardus OS'es])
AM_CONDITIONAL(OS_TYPE_SOLARIS, test x$with_os_type = xsolaris, [Running os Solaris OS'es])
AM_CONDITIONAL(OS_TYPE_FREEBSD, test x$with_os_type = xfreebsd, [Running on FreeBSD OS'es])

AC_ARG_WITH(pam-include, [  --with-pam-include=<file>  pam file to include])

#### Set up pam file to include (distro-tweaks required)
if ! test -z "$with_pam_include"; then
   PAM_FILE_INCLUDE_AUTH=$with_pam_include
   PAM_FILE_INCLUDE_ACCOUNT=$with_pam_include
   PAM_FILE_INCLUDE_PASSWORD=$with_pam_include
   PAM_FILE_INCLUDE_SESSION=$with_pam_include
elif test x$with_os_type = xredhat -o x$with_os_type = xgentoo -o x$with_os_type = xpardus ; then
   PAM_FILE_INCLUDE_AUTH=system-auth
   PAM_FILE_INCLUDE_ACCOUNT=system-auth
   PAM_FILE_INCLUDE_PASSWORD=system-auth
   PAM_FILE_INCLUDE_SESSION=system-auth
elif test x$with_os_type = xsuse -o x$with_os_type = xsolaris ; then
   PAM_FILE_INCLUDE_AUTH=common-auth
   PAM_FILE_INCLUDE_ACCOUNT=common-account
   PAM_FILE_INCLUDE_PASSWORD=common-password
   PAM_FILE_INCLUDE_SESSION=common-session
elif test x$with_os_type = xfreebsd ; then
    PAM_FILE_INCLUDE_AUTH=system
    PAM_FILE_INCLUDE_ACCOUNT=system
    PAM_FILE_INCLUDE_PASSWORD=system
    PAM_FILE_INCLUDE_SESSION=system
else
   PAM_FILE_INCLUDE_AUTH=system-auth
   PAM_FILE_INCLUDE_ACCOUNT=system-auth
   PAM_FILE_INCLUDE_PASSWORD=system-auth
   PAM_FILE_INCLUDE_SESSION=system-auth
fi

AC_SUBST(PAM_FILE_INCLUDE_AUTH)
AC_SUBST(PAM_FILE_INCLUDE_ACCOUNT)
AC_SUBST(PAM_FILE_INCLUDE_PASSWORD)
AC_SUBST(PAM_FILE_INCLUDE_SESSION)
AC_DEFINE_UNQUOTED(PAM_FILE_INCLUDE_AUTH, "$PAM_FILE_INCLUDE_AUTH", [pam file auth])
AC_DEFINE_UNQUOTED(PAM_FILE_INCLUDE_ACCOUNT, "$PAM_FILE_INCLUDE_ACCOUNT", [pam file account])
AC_DEFINE_UNQUOTED(PAM_FILE_INCLUDE_PASSWORD, "$PAM_FILE_INCLUDE_PASSWORD", [pam file password])
AC_DEFINE_UNQUOTED(PAM_FILE_INCLUDE_SESSION, "$PAM_FILE_INCLUDE_SESSION", [pam file session])

dnl ---------------------------------------------------------------------------
dnl - check OS
dnl ---------------------------------------------------------------------------
case "$host_os" in
  *linux*)
	;;
  *solaris*)
	AC_DEFINE([HAVE_SOLARIS], 1, [Is this a Solaris system?])
	;;
  *freebsd*)
  	AC_DEFINE([HAVE_FREEBSD], 1, [Is this a FreeBSD system?])
	;;
esac

GOBJECT_INTROSPECTION_CHECK([0.6.2])

AC_ARG_ENABLE([examples],
              AS_HELP_STRING([--enable-examples], [Build the example programs]),,
              [enable_examples=yes])

AM_CONDITIONAL(BUILD_EXAMPLES, test "x$enable_examples" = "xyes")

# ********************
# Internationalization
# ********************

IT_PROG_INTLTOOL([0.40.0])
GETTEXT_PACKAGE=polkit-1
AC_SUBST([GETTEXT_PACKAGE])
AM_GLIB_GNU_GETTEXT
AC_DEFINE_UNQUOTED([GETTEXT_PACKAGE],["$GETTEXT_PACKAGE"],[gettext domain])

AC_OUTPUT([
Makefile
actions/Makefile
data/Makefile
data/polkit-1
data/polkit-gobject-1.pc
data/polkit-backend-1.pc
data/polkit-agent-1.pc
src/Makefile
src/polkit/Makefile
src/polkitbackend/Makefile
src/polkitagent/Makefile
src/polkitd/Makefile
src/programs/Makefile
src/examples/Makefile
src/nullbackend/Makefile
docs/version.xml
docs/extensiondir.xml
docs/Makefile
docs/polkit/Makefile
docs/man/Makefile
po/Makefile.in
test/Makefile
test/polkit/Makefile
test/polkitbackend/Makefile
])

dnl ==========================================================================
echo "
                  polkit $VERSION
                =================

        prefix:                     ${prefix}
        libdir:                     ${libdir}
        libexecdir:                 ${libexecdir}
        bindir:                     ${bindir}
        sbindir:                    ${sbindir}
        datadir:                    ${datadir}
        sysconfdir:                 ${sysconfdir}
        localstatedir:              ${localstatedir}
        docdir:                     ${docdir}

        compiler:                   ${CC}
        cflags:                     ${CFLAGS}
        cppflags:                   ${CPPFLAGS}
        xsltproc:                   ${XSLTPROC}
	introspection:		    ${found_introspection}

        Distribution/OS:            ${with_os_type}
        Authentication framework:   ${POLKIT_AUTHFW}
        Session tracking:           ${SESSION_TRACKING}
        PAM support:                ${have_pam}"

if test "$have_pam" = yes ; then
echo "
        PAM file auth:              ${PAM_FILE_INCLUDE_AUTH}
        PAM file account:           ${PAM_FILE_INCLUDE_ACCOUNT}
        PAM file password:          ${PAM_FILE_INCLUDE_PASSWORD}
        PAM file session:           ${PAM_FILE_INCLUDE_SESSION}"
fi
echo "
        Maintainer mode:            ${USE_MAINTAINER_MODE}
        Building verbose mode:      ${enable_verbose_mode}
        Building api docs:          ${enable_gtk_doc}
        Building man pages:         ${enable_man_pages}
        Building examples:          ${enable_examples}

"

echo "NOTE: The directory ${sysconfdir}/polkit-1/localauthority must be owned"
echo "      by root and have mode 700"
echo

echo "NOTE: The directory ${localstatedir}/lib/polkit-1 must be owned"
echo "      by root and have mode 700"
echo

echo "NOTE: The file ${libexecdir}/polkit-agent-helper-1 must be owned"
echo "      by root and have mode 4755 (setuid root binary)"
echo

echo "NOTE: The file ${bindir}/pkexec must be owned by root and"
echo "      have mode 4755 (setuid root binary)"
echo

