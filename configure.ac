AC_INIT(Chimbuko Provenance Database Converter, 1.0)
: ${CXXFLAGS=""}   #Disable default optimization
AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects])
AC_LANG(C++)
AC_PROG_CXX
AM_PROG_AR
LT_INIT

# Check for c++17
CXXFLAGS+=" -std=c++17"
AC_MSG_CHECKING([for c++17 compatibility])
AC_COMPILE_IFELSE( [AC_LANG_PROGRAM([[]],
                                    [[]])],
                   [AC_MSG_RESULT([yes])],
                   [AC_MSG_FAILURE(["Could not compile with CXXFLAGS $CXXFLAGS"])]
                  )

#Check for duckdb library
AC_ARG_WITH([duckdb], AS_HELP_STRING([--with-duckdb], [Specify DuckDB install directory]),[],[])
if test "x$with_duckdb" != "x"; then
   CPPFLAGS+=" -I$with_duckdb/include"
   LIBS+=" -L$with_duckdb/lib -lduckdb" 

   AC_LINK_IFELSE(
 	[
		AC_LANG_PROGRAM(
			[[ #include<duckdb.h>
			   #include<cassert>
                            ]], [[     duckdb_database db;
			               duckdb_connection con;
				       if (duckdb_open("database.ddb", &db) == DuckDBError) assert(0);
				       if (duckdb_connect(db, &con) == DuckDBError) assert(0);
				 ]]
			)
	], [duckdb_links=yes], [duckdb_links=no]
	)
   if test	"x${duckdb_links=no}" = "xno"; then
       AC_MSG_FAILURE(["DuckDB is required"])
   fi
else
	AC_MSG_FAILURE(["DuckDB install path must be specified with --with-duckdb"])
fi


SONATA_CFLAGS=$(pkg-config --cflags sonata-server 2>&1)
if [[ $(echo ${SONATA_CFLAGS} | grep -c "not found") -eq 1 ]]; then
    AC_MSG_FAILURE(["Cannot find sonata-server configuration with pkg-config"])
else
    CXXFLAGS+=" ${SONATA_CFLAGS} "
    SONATA_LDFLAGS=$(pkg-config --libs sonata-server 2>&1)
    LDFLAGS+=" ${SONATA_LDFLAGS} " 
fi

AC_CHECK_LIB([sonata-client], [_init], [],  [AC_MSG_FAILURE([Could not link to sonata-client])]  )
AC_CHECK_LIB([sonata-server], [_init], [],  [AC_MSG_FAILURE([Could not link to sonata-server])]  )
AC_CHECK_LIB([sonata-admin], [_init], [],  [AC_MSG_FAILURE([Could not link to sonata-admin])]  )
AC_CHECK_LIB([mercury], [_init], [],  [AC_MSG_FAILURE([Could not link to mercury])]  )
AC_CHECK_LIB([margo], [_init], [],  [AC_MSG_FAILURE([Could not link to margo])]  )

JSON_CFLAGS=$(pkg-config --cflags nlohmann_json 2>&1)
if [[ $(echo ${JSON_CFLAGS} | grep -c "not found") -eq 1 ]]; then
    AC_MSG_FAILURE([Cannot find nlohmann_json configuration with pkg-config])
else
   CXXFLAGS+=" ${JSON_CFLAGS} "

   AC_LINK_IFELSE(
 	[
		AC_LANG_PROGRAM(
			[[ #include<nlohmann/json.hpp> ]], [[     nlohmann::json result;  ]]
			)
	], [json_links=yes], [json_links=no]
	)
   if test	"x${json_links=no}" = "xno"; then
       AC_MSG_FAILURE(["Could not compile with nlohmann json"])
   fi
fi



AC_CONFIG_HEADERS([include/config.h])
AC_SUBST([PS_FLAGS])

AC_CONFIG_SRCDIR([src/dummy])
AC_CONFIG_FILES([Makefile src/Makefile app/Makefile include/Makefile])

AC_OUTPUT
