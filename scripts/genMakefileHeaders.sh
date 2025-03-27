#Generate a Makefile for the include directory (run from inside the directory)
echo -n 'nobase_include_HEADERS = config.h ' > Makefile.am

for i in $(find . -name '*.h' | sed 's/^\.\///'); do
    echo -n "$i " >> Makefile.am
done
