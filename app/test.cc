#include <ddb_wrapper.h>
#include <pdb_schema.h>
#include <pdb_global_schema.h>

#include <sonata/Admin.hpp>
#include <sonata/Provider.hpp>
#include <sonata/Client.hpp>
#include <sstream>
#include <set>

//Parse the collection to obtain specific records from the set recidxs and return the number of parsed records. These indices will be removed from this set once parsed
template<typename Into>
size_t parseSpecificRecords(Into &into, sonata::Database &db, const std::string &col_name, std::unordered_set<uint64_t> &recidxs){
  if(recidxs.size() == 0) return 0;
  
  sonata::Collection col = db.open(col_name);
  size_t size;
  try{
    size = col.size();
  }catch(const sonata::Exception &e){
    return 0; //calling size on an empty collection appears to throw an error; perhaps this quantity is only populated once at least one write takes place?
  }
    
  if(size == 0) return 0; //just in case!

  size_t r = 0;
  std::vector<uint64_t> toremove;
  for(uint64_t idx: recidxs){
    nlohmann::json rec;
    bool exists = true;
    try{    
      col.fetch(idx, &rec);
    }catch(const sonata::Exception &e){
      exists = false;
    }
    if(exists){
      std::cout << "Parsing record " << idx << std::endl;   
      into.import(rec);
      ++r;
      toremove.push_back(idx);
    }
  }

  for(auto tr : toremove)
    recidxs.erase(tr);
  
  return r;
}

//Parse the collection and return the number of records 
template<typename Into>
size_t parseCollection(Into &into, sonata::Database &db, const std::string &col_name, int *nrecord_max = nullptr){
  if(nrecord_max != nullptr && *nrecord_max <= 0) return 0;
  
  int r=0;
   
  sonata::Collection col = db.open(col_name);
  size_t size;
  try{
    size = col.size();
  }catch(const sonata::Exception &e){
    return 0; //calling size on an empty collection appears to throw an error; perhaps this quantity is only populated once at least one write takes place?
  }
    
  if(size == 0) return 0; //just in case!
   
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
      std::cout << "Parsing record " << idx << std::endl;      
      into.import(rec);
      ++r;
      if(nrecord_max != nullptr && r >= *nrecord_max) return r;
    }
  }
  return r;
}


nlohmann::json getFirst(sonata::Database &db, const std::string &col_name){
  sonata::Collection col = db.open(col_name);
  size_t size;
  try{
    size = col.size();
  }catch(const sonata::Exception &e){
    return nlohmann::json::object(); //calling size on an empty collection appears to throw an error; perhaps this quantity is only populated once at least one write takes place?
  }
    
  if(size == 0) return nlohmann::json::object(); //just in case!
   
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
      return rec;
    }
  }
  return nlohmann::json::object();
}


std::vector<uint64_t> getRecordIds(sonata::Database &db, const std::string &collection){
  std::stringstream q;
  q << "$ids = [];\n";
  q << "while(($member = db_fetch('" << collection<< "')) != NULL) {\n";
  q << "   array_push($ids, $member.__id);\n";
  q << "}\n";
  std::unordered_set<std::string> vars;
  vars.insert("ids");
  vars.insert("__output__");
  std::unordered_map<std::string, std::string> result;
  db.execute(q.str(), vars, &result);
  std::cout << result["ids"] << std::endl;
  std::cout << result["__output__"] << std::endl;

  std::vector<uint64_t> out;
  return out;
}

std::vector<nlohmann::json> dump(sonata::Database &db, const std::string &collection){
  sonata::Collection col = db.open(collection);
  
  std::string query = "function($a){ return true; }";

  //nlohmann::json result = nlohmann::json::array();
  std::vector<std::string> sresults;
  col.filter(query, &sresults);
  for(auto const &s : sresults){
    std::cout << s << std::endl;
  }
  return std::vector<nlohmann::json>();
}

std::unordered_set<uint64_t> splitRecordIds(const std::string& str) {
  std::unordered_set<uint64_t> recs;
  std::stringstream ss(str);
  std::string token;
  while (std::getline(ss, token, '.')) {
    uint64_t r;
    std::stringstream ss2; ss2 << token; ss2 >> r;
    recs.insert(r);
  }
  return recs;
}

int main(int argc, char **argv){
  if(argc < 3){
    std::cout << "Usage: <binary> <provdb_dir> <outfile> <options>" << std::endl
	      << "Options:" << std::endl
	      << "-nshards <num> : Set the number of shards" <<std::endl
	      << "-nrecord_max <num> : Cap on how many records to import per collection (over all shards in the case of the main DB)." << std::endl
	      << "-specific_records_anom <shard> <idx1.idx2.idx3>: In this shard, parse only specific records from the \"anomalies\" collection. Indices should be in the form $shard#$idx (eg 1:32) separated by a period (.). This overrides -nrecord_max for this shard but still counts towards it." << std::endl
      	      << "-specific_records_funcstats <idx.idx2.idx3....>: As above but for the \"func_stats\" collection of the global database." << std::endl;
      
    return 0;
  }
  std::string pdb_dir = argv[1];
  std::string out_file = argv[2];
  
  int nshards = 1;
  
  int arg=3;
  int nrecord_max=0;
  bool nrecord_max_set = false;
  
  std::map<int,  std::unordered_set<uint64_t> > anom_recs;
  std::unordered_set<uint64_t> funcstats_recs;
  bool spec_funcstats_recs=false;
  
  while(arg < argc){
    std::string sarg(argv[arg]);
    if(sarg == "-nshards"){
      std::stringstream ss; ss << argv[arg+1]; ss >> nshards;
      arg+=2;
    }else if(sarg == "-nrecord_max"){ 
      std::stringstream ss; ss << argv[arg+1]; ss >> nrecord_max;
      nrecord_max_set = true;
      arg+=2;
    }else if(sarg == "-specific_records_anom"){
      int shard;
      std::stringstream ss; ss << argv[arg+1]; ss >> shard;      
      anom_recs[shard] = splitRecordIds(argv[arg+2]);
      arg+=3;
    }else if(sarg == "-specific_records_funcstats"){
      funcstats_recs = splitRecordIds(argv[arg+1]);
      spec_funcstats_recs = true;
      arg+=2;      
    }else{
      std::stringstream ss; ss << "Unknown argument: \"" << sarg << "\"";      
      throw std::runtime_error(ss.str());
    }
  }
      
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
  int nrecord_max_anom = nrecord_max;
  
  for(int s=0;s<nshards;s++){
    std::cout << "Parsing anomalies from shard " << s << std::endl;
    auto sit = anom_recs.find(s);

    size_t parsed;
    if(sit != anom_recs.end()){
      parsed = parseSpecificRecords(tables, *databases[s], "anomalies", sit->second);
    }else{      
      parsed = parseCollection(tables, *databases[s], "anomalies", nrecord_max_set ? &nrecord_max_anom: nullptr);
    }
    std::cout << "Parsed " << parsed << " records from shard " << s << std::endl;
    if(nrecord_max_set) nrecord_max_anom -= parsed;
  }
  
  //parse the global database
  provDBglobalFuncStatsTables glob_tables(con);  
  std::cout << "Parsing func_stats from global database" << std::endl;
  if(spec_funcstats_recs){
    size_t parsed = parseSpecificRecords(glob_tables, *glob_db, "func_stats", funcstats_recs);
    std::cout << "Parsed " << parsed << " records from global database" << std::endl;
  }else{
    size_t parsed = parseCollection(glob_tables, *glob_db, "func_stats", nrecord_max_set ? &nrecord_max : nullptr);
    std::cout << "Parsed " << parsed << " records from global database" << std::endl;
  }

  tables.write();
  glob_tables.write();
  duckdb_disconnect(&con);
  duckdb_close(&db);
  return 0;
}
