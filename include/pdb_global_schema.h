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
  virtual const nlohmann::json & getDataLayer(const nlohmann::json &rec) const =  0;
  
  void import(const nlohmann::json &rec){
    const nlohmann::json &data = this->getDataLayer(rec);
    
    int r = tab.addRow();
#define DOIT_KEY(T,NM) { T v = rec[#NM]; tab(r,#NM) = v; }
#define DOIT(T,NM) { T v = data[#NM]; tab(r,#NM) = v; }
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
  const nlohmann::json & getDataLayer(const nlohmann::json &rec) const override{
    return rec["anomaly_metrics"]["anomaly_count"];
  }
};
  


struct provDBglobalFuncStatsTables{
  FuncAnomalyCountStats func_anomaly_count_stats;

  provDBglobalFuncStatsTables(duckdb_connection &con): func_anomaly_count_stats(con){  }

  void import(const nlohmann::json &rec){
    func_anomaly_count_stats.import(rec);
  }
  
  void write(){
    func_anomaly_count_stats.write();
  }
  void clear(){
    func_anomaly_count_stats.clear();
  }
  
};
