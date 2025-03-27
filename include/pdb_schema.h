#pragma once
#include "ddb_wrapper.h"
#include <nlohmann/json.hpp>
#include <unordered_set>
#include <tuple>

class AnomaliesTable{
  duckdb_connection &con;
  Table tab;

#define ENTRIES \
    DOIT(std::string, event_id); \
    DOIT(uint64_t,entry); \
    DOIT(uint64_t,exit); \
    DOIT(int,fid); \
    DOIT(int,pid); \
    DOIT(int,rid); \
    DOIT(int,tid); \
    DOIT2(int,io_step_index, io_step); \
    DOIT(uint64_t,runtime_exclusive); \
    DOIT(double,outlier_score); \
    DOIT(double,outlier_severity); \
    DOIT(bool, is_gpu_event); 
  
public:
  AnomaliesTable(duckdb_connection &con): tab("anomalies"), con(con){
#define DOIT(T,NM) tab.addColumn<T>(#NM)
#define DOIT2(T,NM,NM2) tab.addColumn<T>(#NM)
    ENTRIES;
#undef DOIT
#undef DOIT2
    tab.define(con);
  }
    
  void import(const nlohmann::json &rec){
    int r = tab.addRow();
#define DOIT(T,NM){ T v = rec[#NM];  tab(r,#NM) = v; }
#define DOIT2(T,NM,NM2){ T v = rec[#NM2];  tab(r,#NM) = v; }
    ENTRIES;
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

class CallStackTables{
  Table call_stack_events; //events that appear in call stacks
  Table call_stacks; //map of anomaly event_id to one or more entries in call_stack_events
  std::unordered_set<std::string> call_stack_events_keys; //even if table is cleared when flushing to disk, we need to maintain a list of events in the call_stack_events table to ensure uniqueness
  
  duckdb_connection &con;

#define CALL_STACK_EVENTS_ENTRIES \
      DOIT(std::string,event_id); \
      DOIT(uint64_t,entry); \
      DOIT(uint64_t,exit); \
      DOIT(int, fid); \
      DOIT(bool, is_anomaly);
  
#define CALL_STACKS_ENTRIES \
  DOIT(std::string, event_id);			\
  DOIT(std::string, call_stack_entry_id);

public:
  CallStackTables(duckdb_connection &con): call_stacks("call_stacks"), call_stack_events("call_stack_events"), con(con){
#define DOIT(T,NM) call_stack_events.addColumn<T>(#NM)
    CALL_STACK_EVENTS_ENTRIES;
#undef DOIT

#define DOIT(T,NM) call_stacks.addColumn<T>(#NM)
    CALL_STACKS_ENTRIES;
#undef DOIT
    
    call_stacks.define(con);
    call_stack_events.define(con);
  }
  

  void import(const nlohmann::json &rec){
    auto const &cs = rec["call_stack"];
    std::string event_id = rec["event_id"];
    
    for(size_t i=0;i<cs.size();i++){
      std::string cs_eid = cs[i]["event_id"];

      {
	int r = call_stacks.addRow();
	call_stacks(r,"event_id") = event_id;
	call_stacks(r,"call_stack_entry_id") = cs_eid;
      }
	
      auto ck = call_stack_events_keys.insert(cs_eid);
      if(ck.second){ //key did not previously exist
	int r = call_stack_events.addRow();
#define DOIT(T,NM){ T v = cs[i][#NM];  call_stack_events(r,#NM) = v; }
	CALL_STACK_EVENTS_ENTRIES;
#undef DOIT
	
      }
    }
  }

  void write(){
    call_stacks.write(con);
    call_stack_events.write(con);
  }
  void clear(){
    call_stacks.clear();
    call_stack_events.clear();
  }
};




class ExecWindowTables{
  Table exec_window_events; //events that appear in exec_windows
  Table exec_windows; //map of anomaly event_id to one or more entries in exec_window_events
  std::unordered_set<std::string> exec_window_events_keys; //even if table is cleared when flushing to disk, we need to maintain a list of events in the exec_window_events table to ensure uniqueness
  
  duckdb_connection &con;

#define EXEC_WINDOW_EVENTS_ENTRIES \
      DOIT(std::string,event_id); \
      DOIT(uint64_t,entry); \
      DOIT(uint64_t,exit); \
      DOIT(int, fid); \
      DOIT(bool, is_anomaly); \
      DOIT(std::string, parent_event_id);
 
#define EXEC_WINDOW_ENTRIES \
  DOIT(std::string, event_id);			\
  DOIT(std::string, exec_window_entry_id);

public:
  ExecWindowTables(duckdb_connection &con): exec_windows("exec_windows"), exec_window_events("exec_window_events"), con(con){
#define DOIT(T,NM) exec_window_events.addColumn<T>(#NM)
    EXEC_WINDOW_EVENTS_ENTRIES;
#undef DOIT

#define DOIT(T,NM) exec_windows.addColumn<T>(#NM)
    EXEC_WINDOW_ENTRIES;
#undef DOIT
    
    exec_windows.define(con);
    exec_window_events.define(con);
  }
  
  void import(const nlohmann::json &rec){
    auto const &cs = rec["event_window"]["exec_window"];
    std::string event_id = rec["event_id"];
    
    for(size_t i=0;i<cs.size();i++){
      std::string cs_eid = cs[i]["event_id"];

      {
	int r = exec_windows.addRow();
	exec_windows(r,"event_id") = event_id;
	exec_windows(r,"exec_window_entry_id") = cs_eid;
      }
	
      auto ck = exec_window_events_keys.insert(cs_eid);
      if(ck.second){ //key did not previously exist
	int r = exec_window_events.addRow();
#define DOIT(T,NM){ T v = cs[i][#NM];  exec_window_events(r,#NM) = v; }
	EXEC_WINDOW_EVENTS_ENTRIES;
#undef DOIT
	
      }
    }
  }

  void write(){
    exec_windows.write(con);
    exec_window_events.write(con);
  }
  void clear(){
    exec_windows.clear();
    exec_window_events.clear();
  }
};


class IOstepTable{
  Table io_steps;

  typedef std::tuple<int,int,int> keyType;
  
  struct keyHash{ 
    size_t operator()(const keyType &x) const{ 
      return std::get<0>(x) ^ std::get<1>(x) ^ std::get<2>(x); 
    }
  };
  
  std::unordered_set<keyType, keyHash> io_steps_keys; //ensure each io step only appears once in the table
  
  duckdb_connection &con;

#define IO_STEPS_ENTRIES \
      DOIT(int, io_step); \
      DOIT(int, pid); \
      DOIT(int, rid); \
      DOIT(uint64_t,io_step_tstart); \
      DOIT(uint64_t,io_step_tend); 

public:
  IOstepTable(duckdb_connection &con): io_steps("io_steps"), con(con){
#define DOIT(T,NM) io_steps.addColumn<T>(#NM)
    IO_STEPS_ENTRIES;
#undef DOIT
   
    io_steps.define(con);
  }
  
  void import(const nlohmann::json &rec){
    int step = rec["io_step"];
    int pid = rec["pid"];
    int rid = rec["rid"];
    
    auto ck = io_steps_keys.insert(std::make_tuple(pid,rid,step));
    if(ck.second){
      int r = io_steps.addRow();
#define DOIT(T,NM){ T v = rec[#NM];  io_steps(r,#NM) = v; }
      IO_STEPS_ENTRIES;
#undef DOIT
    }
  }

  void write(){
    io_steps.write(con);
  }
  void clear(){
    io_steps.clear();
  }
};


class GPUanomaliesTable{
  duckdb_connection &con;
  Table gpu_parents;
  Table gpu_anomalies;

  std::unordered_set<std::string> gpu_parents_keys;

#define GPU_PARENTS_ENTRIES \
  DOIT(std::string, event_id); \
  DOIT(int, tid);

  //TODO: call stacks for parents
  
  
#define GPU_ANOMALIES_ENTRIES \
    DOIT(std::string, event_id); \
    DOIT_LOC(int, context); \
    DOIT_LOC(int, device); \
    DOIT_LOC(int, stream); \
    DOIT_SPECIAL(std::string, gpu_parent_event_id);
    
public:
  GPUanomaliesTable(duckdb_connection &con): gpu_anomalies("gpu_anomalies"), gpu_parents("gpu_parents"), con(con){
#define DOIT(T,NM) tab.addColumn<T>(#NM)
#define DOIT_SPECIAL(T,NM) DOIT(T,NM)
#define DOIT_LOC(T,NM) DOIT(T,NM)
    {
      auto &tab = gpu_parents;
      GPU_PARENTS_ENTRIES;
    }
    {
      auto &tab = gpu_anomalies;
      GPU_ANOMALIES_ENTRIES;
    }
#undef DOIT
#undef DOIT_SPECIAL
#undef DOIT_LOC
    
    gpu_parents.define(con);
    gpu_anomalies.define(con);
  }
    
  void import(const nlohmann::json &rec){
    if(rec["is_gpu_event"].template get<bool>()){
      const nlohmann::json &gpu_loc = rec["gpu_location"];	
      int r = gpu_anomalies.addRow();
#define DOIT(T,NM){ T v = rec[#NM];  gpu_anomalies(r,#NM) = v; }
#define DOIT_LOC(T,NM){ T v = gpu_loc[#NM]; gpu_anomalies(r,#NM) = v; }
#define DOIT_SPECIAL(T,NM)
	GPU_ANOMALIES_ENTRIES;
#undef DOIT
#undef DOIT_LOC
#undef DOIT_SPECIAL
      
      if(!rec["gpu_parent"].is_string()){ //if string it is an error, perhaps due to missing correlation ID
	const nlohmann::json &parent_info = rec["gpu_parent"];
	
	gpu_anomalies(r,"gpu_parent_event_id") = parent_info["event_id"].template get<std::string>();
	auto ck = gpu_parents_keys.insert(parent_info["event_id"]);
	if(ck.second){
	  int s = gpu_parents.addRow();
#define DOIT(T,NM){ T v = parent_info[#NM];  gpu_parents(s,#NM) = v; }
	  GPU_PARENTS_ENTRIES;
#undef DOIT
	}
      }else{
	gpu_anomalies(r,"gpu_parent_event_id") = rec["gpu_parent"].template get<std::string>(); //store whatever the error string was
      }
    }   
  }

  void write(){
    gpu_parents.write(con);
    gpu_anomalies.write(con);
  }
  void clear(){
    gpu_parents.clear();
    gpu_anomalies.clear();
  }
};






struct provDBtables{
#define TABLES	 \
  DOIT(AnomaliesTable, anomalies) \
  DOIT(CallStackTables, call_stack) \
  DOIT(ExecWindowTables, exec_window) \
  DOIT(IOstepTable, io_steps) \
  LAST(GPUanomaliesTable, gpu_anomalies)

#define DOIT(T,NM) T NM;
#define LAST(T,NM) DOIT(T, NM)
  TABLES
#undef DOIT
#undef LAST  

#define DOIT(T, NM) NM(con),
#define LAST(T, NM) NM(con)  
  provDBtables(duckdb_connection &con): TABLES{  }
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
#undef TABLES
};


