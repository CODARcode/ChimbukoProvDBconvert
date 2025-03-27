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
    DOIT(double,outlier_severity);   
  
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








struct provDBtables{
  AnomaliesTable anomalies;
  CallStackTables call_stack;
  ExecWindowTables exec_window;
  IOstepTable io_steps;
  
  provDBtables(duckdb_connection &con): anomalies(con), call_stack(con), exec_window(con), io_steps(con){  }

  void import(const nlohmann::json &rec){
    anomalies.import(rec);
    call_stack.import(rec);
    exec_window.import(rec);
    io_steps.import(rec);
  }
  
  void write(){
    anomalies.write();
    call_stack.write();
    exec_window.write();
    io_steps.write();
  }
  void clear(){
    anomalies.clear();
    call_stack.clear();
    exec_window.clear();
    io_steps.clear();
  }
  
};


