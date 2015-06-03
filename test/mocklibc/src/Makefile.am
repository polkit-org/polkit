
lib_LTLIBRARIES = libmocklibc.la
libmocklibc_la_SOURCES = pwd.c grp.c netdb.c netgroup.c netgroup.h

bin_PROGRAMS = mocklibc-debug-netgroup
mocklibc_debug_netgroup_SOURCES = netgroup-debug.c netgroup-debug.h
mocklibc_debug_netgroup_LDADD = libmocklibc.la


-include $(top_srcdir)/git.mk
