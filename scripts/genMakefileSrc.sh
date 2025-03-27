out=Makefile.am
echo 'AM_CPPFLAGS = -I$(top_srcdir)/include' > ${out}
echo 'lib_LTLIBRARIES = libchimbuko_provdb_convert.la' >> ${out}
echo -n 'libchimbuko_provdb_convert_la_SOURCES =' >> ${out}

for i in $(find . -name '*.cc' | sed 's/^\.\///'); do
    echo -n " $i" >> ${out}
done
echo  "" >> ${out}

echo 'libchimbuko_provdb_convert_la_LDFLAGS = -version-info 0:0:0' >> ${out}
