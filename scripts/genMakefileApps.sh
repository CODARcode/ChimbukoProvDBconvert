#Generate a Makefile for the bin directory (run from inside the directory)

out=Makefile.am
echo 'SUBDIRS =' > ${out}
echo 'AM_CPPFLAGS = -I$(top_srcdir)/include' >> ${out}
echo 'AM_LDFLAGS = -Wl,-rpath=$(prefix)/lib' >> ${out}
echo 'LDADD = -L$(top_builddir)/src -lchimbuko_provdb_convert' >> ${out}
echo 'bindir = $(prefix)/bin' >> ${out}

echo -n 'bin_PROGRAMS = ' >> ${out}

for i in $(find . -name '*.cc' | sed 's/^\.\///' | sed 's/\.cc//'); do
    echo -n "$i " >> ${out}
done
echo '' >> ${out}

for i in $(find . -name '*.cc' | sed 's/^\.\///' | sed 's/\.cc//'); do
    echo "${i}_SOURCES = ${i}.cc " >> ${out}
    echo "${i}_LDADD = \$(LDADD)" >> ${out}
done
echo '' >> ${out}
