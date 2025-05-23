#pragma once
#include "ddb_wrapper.h"
#include <nlohmann/json.hpp>
#include <unordered_set>
#include <tuple>

class RunStatsTable{
  Table tab;
  duckdb_connection &con;
  
#define RUN_STATS_ENTRIES \
  DOIT_KEY(int, fid);				\
  DOIT(double, accumulate); 			\
  DOIT(uint64_t, count);				\
  DOIT(double, mean);				\
  DOIT(double, stddev);				\
  DOIT(double, skewness);				\
  DOIT(double, kurtosis);				\
  DOIT(double, maximum);				\
  DOIT(double, minimum);
  
public:
  RunStatsTable(duckdb_connection &con, const std::string &tab_name): tab(tab_name), con(con){
#define DOIT(T,NM) tab.addColumn<T>(#NM)
#define DOIT_KEY(T,NM) tab.addColumn<T>(#NM)
    RUN_STATS_ENTRIES;
#undef DOIT
#undef DOIT_KEY
    tab.define(con);
  }

  //Get the layer from where the runstats data can be extracted
  virtual nlohmann::json const* getDataLayer(const nlohmann::json &rec) const =  0;
  
  void import(const nlohmann::json &rec){
    nlohmann::json const *data_p = this->getDataLayer(rec);
    if(data_p == nullptr) return;

    int r = tab.addRow();
#define DOIT_KEY(T,NM) { T v = rec[#NM]; tab(r,#NM) = v; }
#define DOIT(T,NM) { T v = (*data_p)[#NM]; tab(r,#NM) = v; }
    RUN_STATS_ENTRIES;
#undef DOIT
#undef DOIT_KEY
  }

  void write(){
    tab.write(con);
  }
  void clear(){
    tab.clear();
  }
};

class FuncAnomalyCountStats: public RunStatsTable{
public:
  FuncAnomalyCountStats(duckdb_connection &con): RunStatsTable(con, "func_anomaly_count_stats"){}
  nlohmann::json const* getDataLayer(const nlohmann::json &rec) const override{
    if(rec["anomaly_metrics"].is_null()) return nullptr;
    else return &rec["anomaly_metrics"]["anomaly_count"];
  }
};
class FuncAnomalyScoreStats: public RunStatsTable{
public:
  FuncAnomalyScoreStats(duckdb_connection &con): RunStatsTable(con, "func_anomaly_score_stats"){}
  nlohmann::json const* getDataLayer(const nlohmann::json &rec) const override{
    if(rec["anomaly_metrics"].is_null()) return nullptr;
    else return &rec["anomaly_metrics"]["score"];
  }
};
class FuncAnomalySeverityStats: public RunStatsTable{
public:
  FuncAnomalySeverityStats(duckdb_connection &con): RunStatsTable(con, "func_anomaly_severity_stats"){}
  nlohmann::json const* getDataLayer(const nlohmann::json &rec) const override{
    if(rec["anomaly_metrics"].is_null()) return nullptr;
    else return &rec["anomaly_metrics"]["severity"];
  }
};
class FuncRuntimeProfileInclusiveStats: public RunStatsTable{
public:
  FuncRuntimeProfileInclusiveStats(duckdb_connection &con): RunStatsTable(con, "func_runtime_profile_inclusive_stats"){}
  nlohmann::json const* getDataLayer(const nlohmann::json &rec) const override{
    return &rec["runtime_profile"]["inclusive_runtime"];
  }
};
class FuncRuntimeProfileExclusiveStats: public RunStatsTable{
public:
  FuncRuntimeProfileExclusiveStats(duckdb_connection &con): RunStatsTable(con, "func_runtime_profile_exclusive_stats"){}
  nlohmann::json const* getDataLayer(const nlohmann::json &rec) const override{
    return &rec["runtime_profile"]["exclusive_runtime"];
  }
};  

class FunctionTable{
  Table tab;
  duckdb_connection &con;
  
#define FUNCTION_ENTRIES \
  DOIT(int, fid);				\
  DOIT2(int, pid, app);					\
  DOIT2(std::string, name, fname);
  
public:
  FunctionTable(duckdb_connection &con): tab("functions"), con(con){
#define DOIT(T,NM) tab.addColumn<T>(#NM)
#define DOIT2(T,NM,NM2) tab.addColumn<T>(#NM)
    FUNCTION_ENTRIES;
#undef DOIT
#undef DOIT2
    tab.define(con);
  }

  void import(const nlohmann::json &rec){
    int r = tab.addRow();
#define DOIT(T,NM) { T v = rec[#NM]; tab(r,#NM) = v; }
#define DOIT2(T,NM,NM2) { T v = rec[#NM2]; tab(r,#NM) = v; }
    FUNCTION_ENTRIES;
#undef DOIT
#undef DOIT2
  }

  void write(){
    tab.write(con);
  }
  void clear(){
    tab.clear();
  }
};

class ADmodelTable{
  Table tab;
  duckdb_connection &con;

  bool is_setup;
  bool is_hbos_copod;
  
public:
  ADmodelTable(duckdb_connection &con): tab("ad_models"), con(con), is_setup(false){  }

  static std::vector<uint64_t> getIntVector(const nlohmann::json &v){
    assert(v.is_array());
    std::vector<uint64_t> out(v.size());
    for(size_t i=0;i<v.size();i++)
      out[i] = v[i].template get<uint64_t>();
    return out;
  }
  
  void import(const nlohmann::json &rec){
    int fid = rec["fid"].template get<int>();
    const nlohmann::json &model = rec["model"];
    if(!is_setup){
      if(model.contains("histogram")){
	is_hbos_copod = true;

	tab.addColumn<int>("fid");
	tab.addColumn<double>("bin_width");
	tab.addColumn<double>("first_edge");
	tab.addColumn<uint64_t>("min");
	tab.addColumn<uint64_t>("max");
	tab.addColumn<std::vector<uint64_t> >("bin_counts");
	tab.addColumn<double>("internal_global_threshold");
	tab.define(con);
	
	std::cout << "Identified models are HBOS/COPOD" << std::endl;
      }else{
	throw std::runtime_error("Only HBOS/COPOD are currently implemented");
      }
      is_setup = true;
    }
    
    int r = tab.addRow();
    tab(r, "fid") = fid;

    if(is_hbos_copod){
      const nlohmann::json &hist = model["histogram"];

      tab(r, "bin_width") = hist["Bin width"].template get<double>();
      tab(r, "first_edge") = hist["First edge"].template get<double>();
      tab(r, "min") = hist["Min"].template get<uint64_t>();
      tab(r, "max") = hist["Max"].template get<uint64_t>();
      tab(r, "bin_counts") = getIntVector(model["histogram"]["Bin Counts"]);
      tab(r, "internal_global_threshold") = model["internal_global_threshold"].template get<double>();
    }else{
      assert(0);
    }
      
  }

  void write(){
    tab.write(con);
  }
  void clear(){
    tab.clear();
  }
};
  


struct provDBglobalFuncStatsTables{
#define TABLES	   \
  DOIT(FunctionTable, functions)					\
  DOIT(FuncRuntimeProfileInclusiveStats, func_runtime_profile_inclusive_stats) \
  DOIT(FuncRuntimeProfileExclusiveStats, func_runtime_profile_exclusive_stats) \
  DOIT(FuncAnomalyCountStats, func_anomaly_count_stats)			\
  DOIT(FuncAnomalyScoreStats, func_anomaly_score_stats)			\
  DOIT(FuncAnomalySeverityStats, func_anomaly_severity_stats)
   
#define DOIT(T,NM) T NM;
  TABLES
#undef DOIT
  
  bool dummy;
    
#define DOIT(T, NM) NM(con),
  provDBglobalFuncStatsTables(duckdb_connection &con): TABLES dummy(false) {  }
#undef DOIT

						       
  void import(const nlohmann::json &rec){
#define DOIT(T,NM) NM.import(rec);
    TABLES
#undef DOIT
  }
  
  void write(){
#define DOIT(T,NM) NM.write();
    TABLES
#undef DOIT
  }
  void clear(){
#define DOIT(T,NM) NM.clear();
    TABLES
#undef DOIT
  }

#undef TABLES
};

struct provDBglobalADmodelTables{
#define TABLES	   \
  DOIT(ADmodelTable, ad_models)
   
#define DOIT(T,NM) T NM;
  TABLES
#undef DOIT
  
  bool dummy;
    
#define DOIT(T, NM) NM(con),
  provDBglobalADmodelTables(duckdb_connection &con): TABLES dummy(false) {  }
#undef DOIT
						       
  void import(const nlohmann::json &rec){
#define DOIT(T,NM) NM.import(rec);
    TABLES
#undef DOIT
  }
  
  void write(){
#define DOIT(T,NM) NM.write();
    TABLES
#undef DOIT
  }
  void clear(){
#define DOIT(T,NM) NM.clear();
    TABLES
#undef DOIT
  }

#undef TABLES
};


