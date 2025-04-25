SUBDIRS =
AM_CPPFLAGS = -I$(top_srcdir)/include
AM_LDFLAGS = -Wl,-rpath=$(prefix)/lib
LDADD = -L$(top_builddir)/src -lchimbuko_provdb_convert
bindir = $(prefix)/bin
bin_PROGRAMS = chimbuko_provdb_convert
chimbuko_provdb_convert_SOURCES = chimbuko_provdb_convert.cc 
chimbuko_provdb_convert_LDADD = $(LDADD)

