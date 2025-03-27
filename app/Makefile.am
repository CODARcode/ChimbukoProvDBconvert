SUBDIRS =
AM_CPPFLAGS = -I$(top_srcdir)/include
AM_LDFLAGS = -Wl,-rpath=$(prefix)/lib
LDADD = -L$(top_builddir)/src -lchimbuko_provdb_convert
bindir = $(prefix)/bin
bin_PROGRAMS = test 
test_SOURCES = test.cc 
test_LDADD = $(LDADD)

