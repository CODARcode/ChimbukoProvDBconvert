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
class FuncAnomalyScoreStats: public RunStatsTable{
public:
  FuncAnomalyScoreStats(duckdb_connection &con): RunStatsTable(con, "func_anomaly_score_stats"){}
  const nlohmann::json & getDataLayer(const nlohmann::json &rec) const override{
    return rec["anomaly_metrics"]["score"];
  }
};
class FuncAnomalySeverityStats: public RunStatsTable{
public:
  FuncAnomalySeverityStats(duckdb_connection &con): RunStatsTable(con, "func_anomaly_severity_stats"){}
  const nlohmann::json & getDataLayer(const nlohmann::json &rec) const override{
    return rec["anomaly_metrics"]["severity"];
  }
};
class FuncRuntimeProfileInclusiveStats: public RunStatsTable{
public:
  FuncRuntimeProfileInclusiveStats(duckdb_connection &con): RunStatsTable(con, "func_runtime_profile_inclusive_stats"){}
  const nlohmann::json & getDataLayer(const nlohmann::json &rec) const override{
    return rec["runtime_profile"]["inclusive_runtime"];
  }
};
class FuncRuntimeProfileExclusiveStats: public RunStatsTable{
public:
  FuncRuntimeProfileExclusiveStats(duckdb_connection &con): RunStatsTable(con, "func_runtime_profile_exclusive_stats"){}
  const nlohmann::json & getDataLayer(const nlohmann::json &rec) const override{
    return rec["runtime_profile"]["exclusive_runtime"];
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



struct provDBglobalFuncStatsTables{
  #define TABLES \
    DOIT(FunctionTable, functions) \
    DOIT(FuncRuntimeProfileInclusiveStats, func_runtime_profile_inclusive_stats) \
    DOIT(FuncRuntimeProfileExclusiveStats, func_runtime_profile_exclusive_stats) \
    DOIT(FuncAnomalyCountStats, func_anomaly_count_stats) \
    DOIT(FuncAnomalyScoreStats, func_anomaly_score_stats) \
    LAST(FuncAnomalySeverityStats, func_anomaly_severity_stats) \

#define DOIT(T,NM) T NM;
#define LAST(T,NM) DOIT(T, NM)
  TABLES
#undef DOIT
#undef LAST  

  
#define DOIT(T, NM) NM(con),
#define LAST(T, NM) NM(con)  
  provDBglobalFuncStatsTables(duckdb_connection &con): TABLES {  }
#undef DOIT
#undef LAST  

						       
  void import(const nlohmann::json &rec){
#define DOIT(T,NM) NM.import(rec);
#define LAST(T,NM) DOIT(T, NM)
    TABLES
#undef DOIT
#undef LAST  
  }
  
  void write(){
#define DOIT(T,NM) NM.write();
#define LAST(T,NM) DOIT(T, NM)
    TABLES
#undef DOIT
#undef LAST  
  }
  void clear(){
#define DOIT(T,NM) NM.clear();
#define LAST(T,NM) DOIT(T, NM)
    TABLES
#undef DOIT
#undef LAST  
  }
  
};
