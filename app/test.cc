#include <ddb_wrapper.h>
#include <pdb_schema.h>
#include <pdb_global_schema.h>

#include <sonata/Admin.hpp>
#include <sonata/Provider.hpp>
#include <sonata/Client.hpp>
#include <sstream>
#include <set>

template<typename Into>
void parseSpecificRecords(Into &into, sonata::Database &db, const std::string &col_name, const std::set<uint64_t> &recidxs){
  sonata::Collection col = db.open(col_name);
  size_t size;
  try{
    size = col.size();
  }catch(const sonata::Exception &e){
    return; //calling size on an empty collection appears to throw an error; perhaps this quantity is only populated once at least one write takes place?
  }
    
  if(size == 0) return; //just in case!

  for(uint64_t idx: recidxs){
    nlohmann::json rec;
    bool exists = true;
    try{    
      col.fetch(idx, &rec);
    }catch(const sonata::Exception &e){
      exists = false;
    }
    if(exists){
      into.import(rec);
    }
  }
}


template<typename Into>
void parseCollection(Into &into, sonata::Database &db, const std::string &col_name, int nrecord_max = -1){
  int r=0;
   
  sonata::Collection col = db.open(col_name);
  size_t size;
  try{
    size = col.size();
  }catch(const sonata::Exception &e){
    return; //calling size on an empty collection appears to throw an error; perhaps this quantity is only populated once at least one write takes place?
  }
    
  if(size == 0) return; //just in case!
   
  uint64_t last_idx = col.last_record_id();
  for(uint64_t idx = 0; idx < last_idx; idx++){    
    nlohmann::json rec;
    bool exists = true;
    try{    
      col.fetch(idx, &rec);
    }catch(const sonata::Exception &e){
      exists = false;
    }
    if(exists){
      into.import(rec);
      ++r;
      if(nrecord_max > 0 && r >= nrecord_max) return;
    }
  }
}


void test(){
  std::string pdb_dir = "/home/idies/workspace/Storage/ckelly/persistent/Chimbuko/IMPACTS/test/test_global_QU240/with_select/run_chimbuko_offline/chimbuko/provdb";
  std::string out_file = "provdb.ddb";
  int nshards = 4;
  int nrecord_max =5; //cap on how many records to import. -1=unlimited
  std::set<uint64_t> recs = { 22710 };
    
  //Setup sonata
  thallium::engine engine("na+sm", THALLIUM_SERVER_MODE);

  sonata::Admin admin(engine);
  sonata::Provider provider(engine);
  sonata::Client client(engine);

  std::string addr = (std::string)engine.self();
    
  std::vector<std::string> db_shard_names(nshards);
  std::vector<std::unique_ptr<sonata::Database> > databases(nshards);
  
  for(int s=0;s<nshards;s++){
    {
      std::stringstream ss; ss << "provdb." << s;    
      db_shard_names[s] = ss.str();
    }
    
    std::string config;
    {
      std::stringstream ss; ss << "{ \"path\" : \"" << pdb_dir << "/" << db_shard_names[s] << ".unqlite\" }";
      config = ss.str();
    }

    admin.attachDatabase(addr, 0, db_shard_names[s], "unqlite", config);
    std::cout << "Attaching database " << db_shard_names[s] << std::endl;
    databases[s].reset(new sonata::Database(client.open(addr, 0, db_shard_names[s])));
  }
  std::unique_ptr<sonata::Database> glob_db;
  {
    std::string config;
    {
      std::stringstream ss; ss << "{ \"path\" : \"" << pdb_dir << "/provdb.global.unqlite\" }";
      config = ss.str();
    }   
    admin.attachDatabase(addr,0, "provdb.global", "unqlite", config);
    glob_db.reset(new sonata::Database(client.open(addr, 0, "provdb.global")));
  }
    
  //Setup DuckDB
  duckdb_database db;
  duckdb_connection con;
  remove(out_file.c_str());
  if (duckdb_open(out_file.c_str(), &db) == DuckDBError) assert(0);
  if (duckdb_connect(db, &con) == DuckDBError) assert(0);

  provDBtables tables(con);
  
  //parse "anomalies"
  // for(int s=0;s<nshards;s++){
  //   std::cout << "Parsing anomalies from shard " << s << std::endl;
  //   parseCollection(tables, *databases[s], "anomalies", nrecord_max);
  // }
  std::cout << "Parsing anomalies from shard 0" << std::endl;
  parseSpecificRecords(tables, *databases[0], "anomalies", recs);
  
  //parse the global database
  provDBglobalFuncStatsTables glob_tables(con);
  std::cout << "Parsing func_stats from global database" << std::endl;
  parseCollection(glob_tables, *glob_db, "func_stats", nrecord_max);
  

  tables.write();
  glob_tables.write();
  duckdb_disconnect(&con);
  duckdb_close(&db);
}


void benchmark1(){
  //Test a simple table with float columns as we scale #rows and #cols
  Timer timer;

  //Hot loop; row batches are all added to the same table. Table is *not* flushed to disk
  for(int c=1; c<101; c+=10){
    remove("database.ddb");

    timer.start();
    duckdb_database db;
    duckdb_connection con;
    if (duckdb_open("database.ddb", &db) == DuckDBError) assert(0);
    if (duckdb_connect(db, &con) == DuckDBError) assert(0);

    { //disable checkpointing to disk
      assert(duckdb_query(con, "SET checkpoint_threshold = '100 GB';", NULL) != DuckDBError);
      //assert(duckdb_query(con, "SET checkpoint_threshold = '8 B';", NULL) != DuckDBError);
    }    
    
    Table table("mytable");
    //setup the table
    for(int cc=0;cc<c;cc++) table.addColumn<double>("col"+std::to_string(cc));
    //tell duckdb about our table
    table.define(con); 
    double topen = timer.elapsed_us();

    for(int rbatch_sz=10; rbatch_sz<100000; rbatch_sz*=2){
      table.resizeRows(rbatch_sz); //note that the table represents the unwritten portion here
      for(int r=0;r<rbatch_sz;r++)
	for(int cc=0;cc<c;cc++)
	  table(r,cc) = cc+c*r+3.14;

      for(int rpt=0;rpt<4;rpt++){     
	timer.start();
	table.write(con);
	double twrite = timer.elapsed_us();

	std::cout << "PRE COMMIT: " << table.databaseSize(con) << std::endl;

	//assert(duckdb_query(con, "PRAGMA enable_profiling;", NULL) != DuckDBError);
	//assert(duckdb_query(con, "SET enable_profiling = 'query_tree';", NULL) != DuckDBError);
	//assert(duckdb_query(con, "SET profiling_mode = 'detailed';", NULL) != DuckDBError);
	timer.start();
	table.commit(con);
	double tcommit = timer.elapsed_us();
	//assert(duckdb_query(con, "PRAGMA disable_profiling;", NULL) != DuckDBError);
	
	std::cout << "POST COMMIT: " << table.databaseSize(con) << std::endl;
	
	std::cout << rbatch_sz << "," << c << " " << rbatch_sz * c << " : "
		  << "total append "<< twrite << "us  commit " << tcommit << "us"
		  << ", per row append " << twrite/rbatch_sz << "us  commit " << tcommit/rbatch_sz << "us"
		  << ", per elem append " << twrite/rbatch_sz/c << "us  commit " << tcommit/rbatch_sz/c << "us"
		  << std::endl;
      }
    }
      
    timer.start();
    duckdb_disconnect(&con);
    duckdb_close(&db);
    double tclose = timer.elapsed_us();
  }


  
}






int main(void){
  test();
  //benchmark1();
  return 0;
}
