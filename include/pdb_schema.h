#pragma once
#include "ddb_wrapper.h"
#include <nlohmann/json.hpp>
#include <unordered_set>
#include <unordered_map>
#include <tuple>
#include <sstream>

//The event IDs have the form “$RANK:$IO_STEP:$IDX” (eg “0:12:225”) which are unique only within a given process. To support multiple processes we augment the index to
//$PID:$RANK:$IO_STEP:$IDX
inline std::string getUniqueID(const std::string &process_event_id, int pid){
  std::stringstream ss; ss << pid << ":" << process_event_id;
  return ss.str();
}

const std::unordered_set<std::string> & defaultEventIDnames(){
  static std::unordered_set<std::string> s({ "event_id" });
  return s;
}

//Augment event_ids without too much extra work
template<typename T>
inline T process(const nlohmann::json &rec, const std::string &entry, int pid, const std::unordered_set<std::string> &event_id_nm = defaultEventIDnames()){
  return rec[entry].template get<T>();
}
template<>
inline std::string process<std::string>(const nlohmann::json &rec, const std::string &entry, int pid, const std::unordered_set<std::string> &event_id_nm){
  std::string ret = rec[entry].template get<std::string>();
  if(event_id_nm.count(entry)) ret = getUniqueID(ret,pid);
  return ret;
}

//As counter indices are not unified over all ranks, we build our own mapping of counter name to unique index
uint64_t lookupCounterIndex(const std::string &cname, bool *first = nullptr){
  static std::unordered_map<std::string, uint64_t> cmap;
  static uint64_t cidx_s = 0;

  uint64_t ret;
  auto it = cmap.find(cname);
  if(it == cmap.end()){
    ret = cidx_s;
    cmap[cname] = cidx_s++;
    if(first) *first = true;
    
  }else{
    ret = it->second;
    if(first) *first = false;
  }
  return ret;
}
  

class EventRecordsTable{
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
  EventRecordsTable(duckdb_connection &con, const std::string &table_name): tab(table_name), con(con){
#define DOIT(T,NM) tab.addColumn<T>(#NM)
#define DOIT2(T,NM,NM2) DOIT(T,NM)   
    ENTRIES;
#undef DOIT
#undef DOIT2

    tab.define(con);
  }
    
  void import(const nlohmann::json &rec){
    int r = tab.addRow();
    int pid = rec["pid"].template get<int>();
#define DOIT(T,NM) tab(r,#NM) = process<T>(rec,#NM,pid); 
#define DOIT2(T,NM,NM2) tab(r,#NM) = rec[#NM2].template get<T>();
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

#undef ENTRIES

class AnomaliesTable: public EventRecordsTable{
  public:
  AnomaliesTable(duckdb_connection &con): EventRecordsTable(con, "anomalies"){}
};
class NormalExecsTable: public EventRecordsTable{
  public:
  NormalExecsTable(duckdb_connection &con): EventRecordsTable(con, "normal_execs"){}
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
  
  //If pid = -1 infer from the record
  void import(const nlohmann::json &rec, int pid = -1){
    auto const &cs = rec["call_stack"];
    if(pid == -1)
      pid = rec["pid"].template get<int>();
    
    std::string event_id = getUniqueID(rec["event_id"],pid);
    
    for(size_t i=0;i<cs.size();i++){
      std::string cs_eid = getUniqueID(cs[i]["event_id"],pid);

      {
	int r = call_stacks.addRow();
	call_stacks(r,"event_id") = event_id;
	call_stacks(r,"call_stack_entry_id") = cs_eid;
      }
	
      auto ck = call_stack_events_keys.insert(cs_eid);
      if(ck.second){ //key did not previously exist
	int r = call_stack_events.addRow();
#define DOIT(T,NM) call_stack_events(r,#NM) = process<T>(cs[i],#NM,pid); 
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
    static std::unordered_set<std::string> eid_names({ "event_id", "parent_event_id" });
    
    auto const &cs = rec["event_window"]["exec_window"];
    int pid = rec["pid"].template get<int>();
    std::string event_id = getUniqueID(rec["event_id"],pid);
    
    for(size_t i=0;i<cs.size();i++){
      std::string cs_eid = getUniqueID(cs[i]["event_id"],pid);

      {
	int r = exec_windows.addRow();
	exec_windows(r,"event_id") = event_id;
	exec_windows(r,"exec_window_entry_id") = cs_eid;
      }
	
      auto ck = exec_window_events_keys.insert(cs_eid);
      if(ck.second){ //key did not previously exist
	int r = exec_window_events.addRow();
#define DOIT(T,NM) exec_window_events(r,#NM) = process<T>(cs[i],#NM,pid,eid_names);
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
      return std::hash<int>{}(std::get<0>(x)) ^ std::hash<int>{}(std::get<1>(x)) ^ std::hash<int>{}(std::get<2>(x)); 
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
#define DOIT(T,NM) io_steps(r,#NM) = rec[#NM].template get<T>();
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


class GPUeventsTable{
  duckdb_connection &con;
  Table gpu_parents;
  Table gpu_events;

  std::unordered_set<std::string> gpu_parents_keys;

  CallStackTables* call_stacks; //link the call stacks table to add GPU parent call stacks

#define GPU_PARENTS_ENTRIES \
  DOIT(std::string, event_id); \
  DOIT(int, tid);
  
#define GPU_EVENTS_ENTRIES \
    DOIT(std::string, event_id); \
    DOIT_LOC(int, context); \
    DOIT_LOC(int, device); \
    DOIT_LOC(int, stream); \
    DOIT_SPECIAL(std::string, gpu_parent_event_id);
    
public:
  GPUeventsTable(duckdb_connection &con): gpu_events("gpu_events"), gpu_parents("gpu_parents"), con(con), call_stacks(nullptr){
#define DOIT(T,NM) tab.addColumn<T>(#NM)
#define DOIT_SPECIAL(T,NM) DOIT(T,NM)
#define DOIT_LOC(T,NM) DOIT(T,NM)
    {
      auto &tab = gpu_parents;
      GPU_PARENTS_ENTRIES;
    }
    {
      auto &tab = gpu_events;
      GPU_EVENTS_ENTRIES;
    }
#undef DOIT
#undef DOIT_SPECIAL
#undef DOIT_LOC
    
    gpu_parents.define(con);
    gpu_events.define(con);
  }

  void linkCallStacksTable(CallStackTables* call_stacks_){
    call_stacks = call_stacks_;
  }
    
  void import(const nlohmann::json &rec){
    if(rec["is_gpu_event"].template get<bool>()){
      int pid = rec["pid"].template get<int>();
      
      const nlohmann::json &gpu_loc = rec["gpu_location"];	
      int r = gpu_events.addRow();
#define DOIT(T,NM) gpu_events(r,#NM) = process<T>(rec,#NM,pid); 
#define DOIT_LOC(T,NM) gpu_events(r,#NM) = gpu_loc[#NM].template get<T>(); 
#define DOIT_SPECIAL(T,NM)
	GPU_EVENTS_ENTRIES;
#undef DOIT
#undef DOIT_LOC
#undef DOIT_SPECIAL
      
      if(!rec["gpu_parent"].is_string()){ //if string it is an error, perhaps due to missing correlation ID
	const nlohmann::json &parent_info = rec["gpu_parent"];

	std::string parent_eid = getUniqueID(parent_info["event_id"].template get<std::string>(), pid);
	
	gpu_events(r,"gpu_parent_event_id") = parent_eid;

	//Only add a gpu_parent to the table if it has not been seen before
	auto ck = gpu_parents_keys.insert(parent_eid);
	if(ck.second){
	  int s = gpu_parents.addRow();
#define DOIT(T,NM) gpu_parents(s,#NM) = process<T>(parent_info, #NM, pid);
	  GPU_PARENTS_ENTRIES;
#undef DOIT
	  
	  if(call_stacks == nullptr) throw std::runtime_error("Expect call stacks table to be linked");
	  call_stacks->import(parent_info, pid);
	}
      }else{
	gpu_events(r,"gpu_parent_event_id") = rec["gpu_parent"].template get<std::string>(); //store whatever the error string was
      }
    }   
  }

  void write(){
    gpu_parents.write(con);
    gpu_events.write(con);
  }
  void clear(){
    gpu_parents.clear();
    gpu_events.clear();
  }
};

//The node state from the monitoring plugin
class NodeStateTable{
  duckdb_connection &con;
  Table node_state;

  //For this table the fields are dynamic so we delay setting up the table until we receive the first record
  bool is_setup;
public:
  NodeStateTable(duckdb_connection &con): node_state("node_state"), con(con), is_setup(false){}
    
  void import(const nlohmann::json &rec){
    const nlohmann::json &data = rec["node_state"]["data"];
    if(!is_setup){
      node_state.addColumn<std::string>("event_id");
      node_state.addColumn<uint64_t>("timestamp");
      for(int i=0;i<data.size();i++)
	node_state.addColumn<uint64_t>('"' + data[i]["field"].template get<std::string>() + '"');
      node_state.define(con);
      is_setup=true;
      std::cout << "node_state set up with " << node_state.columns()-2 << " fields" << std::endl;
    }
    int pid = rec["pid"].template get<int>();
    int r = node_state.addRow();
    node_state(r,"event_id") = getUniqueID(rec["event_id"].template get<std::string>(), pid);
    node_state(r,"timestamp") = rec["node_state"]["timestamp"].template get<uint64_t>();
    for(int i=0;i<data.size();i++){
      int col = node_state.columnIndex('"' + data[i]["field"].template get<std::string>() + '"');
      if(col == -1){
	std::cout << "WARNING: Encountered node_state field \"" << data[i]["field"] << "\" not present in first record!" << std::endl;
      }else{
	node_state(r,col) = data[i]["value"].template get<uint64_t>();
      }
    }
  }

  void write(){
    node_state.write(con);
  }
  void clear(){
    node_state.clear();
  }
};


class CounterEventsTables{
  Table counter_names; //counter_idx -> counter_name
  Table counter_events; //anomaly event_id -> { counter_idx, value, timestamp }
  
  duckdb_connection &con;

public:
  CounterEventsTables(duckdb_connection &con): counter_names("counter_names"), counter_events("counter_events"), con(con){
#define DOIT(T,NM) counter_names.addColumn<T>(#NM)
    DOIT(uint64_t, counter_idx);
    DOIT(std::string, counter_name);
#undef DOIT

#define DOIT(T,NM) counter_events.addColumn<T>(#NM)
    DOIT(std::string, event_id);
    DOIT(uint64_t, counter_idx);
    DOIT(uint64_t, value);
    DOIT(uint64_t, timestamp);
#undef DOIT
    
    counter_names.define(con);
    counter_events.define(con);
  }
  
  void import(const nlohmann::json &rec){
    int pid = rec["pid"].template get<int>();
    std::string event_id = getUniqueID(rec["event_id"],pid);

    auto const &cs = rec["counter_events"];
    
    for(size_t i=0;i<cs.size();i++){
      std::string counter_name = cs[i]["counter_name"].template get<std::string>();
      bool first;
      uint64_t counter_idx = lookupCounterIndex(counter_name, &first);

      if(first){ //add to map
	int r = counter_names.addRow();
	counter_names(r,"counter_idx") = counter_idx;
	counter_names(r,"counter_name") = counter_name;
      }

      int r = counter_events.addRow();
      counter_events(r,"event_id") = event_id;
      counter_events(r,"counter_idx") = counter_idx;
      counter_events(r,"value") = cs[i]["counter_value"].template get<uint64_t>();
      counter_events(r,"timestamp") = cs[i]["ts"].template get<uint64_t>();
    }
  }

  void write(){
    counter_names.write(con);
    counter_events.write(con);
  }
  void clear(){
    counter_names.clear();
    counter_events.clear();
  }
};


class CommWindowTables{
  Table comm_windows;
  
  duckdb_connection &con;

                // {
                //     "bytes": 8,
                //     "execdata_key": "0:0:2888",
                //     "pid": 0,
                //     "rid": 0,
                //     "src": 0,
                //     "tag": 0,
                //     "tar": 1,
                //     "tid": 0,
                //     "timestamp": 1745598464682394,
                //     "type": "SEND"
                // },
  
#define COMM_WINDOW_EVENTS_ENTRIES \
      DOIT_EID(std::string,event_id); \
      DOIT2(std::string, parent_event_id, execdata_key); \
      DOIT(uint64_t, bytes);				 \
      DOIT(uint64_t, tag);				 \
      DOIT(uint64_t, src);				 \
      DOIT2(uint64_t, dest, tar);			 \
      DOIT(uint64_t, tid);				 \
      DOIT(uint64_t, timestamp);			 \
      DOIT(std::string, type);


public:
  CommWindowTables(duckdb_connection &con): comm_windows("comm_windows"), con(con){
#define DOIT(T,NM) comm_windows.addColumn<T>(#NM)
#define DOIT2(T,NM,NM2) DOIT(T,NM)
#define DOIT_EID(T,NM) DOIT(T,NM)
    
    COMM_WINDOW_EVENTS_ENTRIES;
#undef DOIT
#undef DOIT2
#undef DOIT_EID
    
    comm_windows.define(con);
  }
  
  void import(const nlohmann::json &rec){
    static std::unordered_set<std::string> eid_names({  "execdata_key" });
    
    auto const &cs = rec["event_window"]["comm_window"];
    int pid = rec["pid"].template get<int>();
    std::string event_id = getUniqueID(rec["event_id"],pid);
    
    for(size_t i=0;i<cs.size();i++){
      int r = comm_windows.addRow();
      comm_windows(r,"event_id") = event_id;
      
#define DOIT(T,NM) comm_windows(r,#NM) = cs[i][#NM].template get<T>()
#define DOIT2(T,NM,NM2) comm_windows(r,#NM) = process<T>(cs[i],#NM2,pid,eid_names)
#define DOIT_EID(T,NM)
      
      COMM_WINDOW_EVENTS_ENTRIES;
#undef DOIT
#undef DOIT2
#undef DOIT_EID
    }
  }

  void write(){
    comm_windows.write(con);
  }
  void clear(){
    comm_windows.clear();
  }
};


class RankNodeTable{
  Table tab;

  typedef std::pair<int,int> keyType;
  
  struct keyHash{ 
    size_t operator()(const keyType &x) const{ 
      return std::hash<int>{}(x.first) ^ std::hash<int>{}(x.second);
    }
  };
  
  std::unordered_set<keyType, keyHash> pid_rid_keys; 
  
  duckdb_connection &con;

#define ENTRIES \
      DOIT(int, pid); \
      DOIT(int, rid); \
      DOIT(std::string, hostname);

public:
  RankNodeTable(duckdb_connection &con): tab("rank_node_map"), con(con){
#define DOIT(T,NM) tab.addColumn<T>(#NM)
    ENTRIES;
#undef DOIT
   
    tab.define(con);
  }
  
  void import(const nlohmann::json &rec){
    int pid = rec["pid"];
    int rid = rec["rid"];
    
    auto ck = pid_rid_keys.insert(std::make_pair(pid,rid));
    if(ck.second){
      int r = tab.addRow();
#define DOIT(T,NM) tab(r,#NM) = rec[#NM].template get<T>();
      ENTRIES;
#undef DOIT
    }
  }

  void write(){
    tab.write(con);
  }
  void clear(){
    tab.clear();
  }
};

#undef ENTRIES



struct provDBtables{
#define SHARED_TABLES \
  DOIT(CallStackTables, call_stack) \
  DOIT(ExecWindowTables, exec_window) \
  DOIT(CommWindowTables, comm_window) \
  DOIT(IOstepTable, io_steps) \
  DOIT(CounterEventsTables, counter_events) \
  DOIT(GPUeventsTable, gpu_events) \
  DOIT(RankNodeTable, node_rank_map) \
  LAST(NodeStateTable, node_state) 

#define ANOM_TABLE  DOIT(AnomaliesTable, anomalies)
#define NORMAL_TABLE  DOIT(NormalExecsTable, normal_execs)

#define ANOM_REC_TABLES ANOM_TABLE SHARED_TABLES
#define NORMAL_REC_TABLES NORMAL_TABLE SHARED_TABLES
#define ALL_TABLES ANOM_TABLE NORMAL_TABLE SHARED_TABLES
  
#define DOIT(T,NM) T NM;
#define LAST(T,NM) DOIT(T, NM)
  ALL_TABLES
#undef DOIT
#undef LAST  

#define DOIT(T, NM) NM(con),
#define LAST(T, NM) NM(con)  
  provDBtables(duckdb_connection &con): ALL_TABLES{
      gpu_events.linkCallStacksTable(&call_stack);
  }
#undef DOIT
#undef LAST
					
  void importAnomaly(const nlohmann::json &rec){
#define DOIT(T,NM) NM.import(rec);
#define LAST(T,NM) DOIT(T, NM)
    ANOM_REC_TABLES
#undef DOIT
#undef LAST  
  }
  void importNormalExec(const nlohmann::json &rec){
#define DOIT(T,NM) NM.import(rec);
#define LAST(T,NM) DOIT(T, NM)
    NORMAL_REC_TABLES
#undef DOIT
#undef LAST  
  }
  
  void write(){
#define DOIT(T,NM) NM.write();
#define LAST(T,NM) DOIT(T, NM)
    ALL_TABLES
#undef DOIT
#undef LAST  
  }
  void clear(){
#define DOIT(T,NM) NM.clear();
#define LAST(T,NM) DOIT(T, NM)
    ALL_TABLES
#undef DOIT
#undef LAST  
  }
#undef ALL_TABLES
#undef SHARED_TABLES
#undef ANOM_TABLE
#undef NORMAL_TABLE
};

