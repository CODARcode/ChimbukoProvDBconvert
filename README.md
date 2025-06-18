The [Chimbuko performance analysis tool](https://github.com/CODARcode/Chimbuko) outputs a "provenance database" containing detailed information on captured performance anomalies and run statistics, stored in a JSON document-store format via the Mochi "Sonata" library built upon UnQlite. 
The ChimbukoProvDBconvert tool converts the UnQlite database to a DuckDB relational database format, allowing the exploitation of more sophisticated data analysis tools such as Pandas, and is part of Chimbuko's offline analysis framework.

# Installation

- [Mochi Sonata](https://github.com/mochi-hpc/mochi-sonata)
- [DuckDB](https://duckdb.org/)

We recommend installing both libraries using [Spack](https://github.com/spack/spack). Once installed

```
./autogen.sh
./configure --prefix=/your/install/path --with-duckdb=/path/to/duckdb/install
make
make install
```

If Spack was used to install DuckDB, you can use `spack location -i duckdb` to locate the install path.

The C++ compiler can be specified by configuring as `CXX=your_compiler ./configure ...` 

# Usage

For basic usage, simply run
```
chimbuko_provdb_convert /path/to/chimbuko/provdb/directory your_output_file -nshards ${nshards}
```
where `${nshards}` is the number of database shards.

### Advanced options:
- `-nrecord_max <num>` : Cap on how many records to import per collection (over all shards in the case of the main DB)."
- `-specific_records_anom <shard> <idx1.idx2.idx3>` : In this shard, parse only specific records from the "anomalies" collection. Indices should be in the form $shard#$idx (eg 1:32) separated by a period (.). This overrides -nrecord_max for this shard but still counts towards it.
- `-specific_records_normal <shard> <idx1.idx2.idx3>`: In this shard, parse only specific records from the "normalexecs" collection. cf. above.
- `-specific_records_funcstats <idx.idx2.idx3....>`: As above but for the "func_stats" collection of the global database.
- `-specific_records_ad_model <idx.idx2.idx3....>`: As above but for the "ad_model" collection of the global database.
