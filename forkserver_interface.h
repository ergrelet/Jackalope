#pragma once
// File defining data structures shared between `forkserverinstrumentation.cpp`
// and `forkserver.cpp`

#define FORKSERVER_SHM "forkserver-shm"
#define FORKSERVER_PIPE "\\\\.\\pipe\\forkserver"
#define FORKSERVER_CHILD_PIPE "\\\\.\\pipe\\forkserver-child"

enum AFL_FORKSERVER_REQUEST_METHOD {
  AFL_CREATE_NEW_CHILD = 0,  // Please spawn a new child!
  AFL_RESUME_CHILD,          // Please start the suspended child.
  AFL_TERMINATE_FORKSERVER,  // Please kill yourself.
};

typedef struct _AFL_FORKSERVER_REQUEST {
  enum AFL_FORKSERVER_REQUEST_METHOD Operation;  // added enum
  union {
    struct {
      BYTE DoNotUseThisField;
    } CreateNewChildInfo;

    struct {
      BYTE DoNotUseThisField;
    } ResumeChildInfo;
  };
} AFL_FORKSERVER_REQUEST;

enum AFL_FORKSERVER_RESULT_STATUS {
  AFL_CHILD_CREATED = 0,
  AFL_CHILD_SUCCESS,
  AFL_CHILD_CRASHED,
  AFL_CHILD_TIMEOUT,
  AFL_CHILD_COVERAGE,  // new coverage event
};

struct AFL_COVERAGE_PACKET {
  char ModuleName[MAX_PATH];
  uintptr_t Rva;
};

struct AFL_FORKSERVER_RESULT {
  enum AFL_FORKSERVER_RESULT_STATUS StatusCode;
  union {
    struct AFL_CHILD_INFO {
      DWORD ProcessId;
      DWORD ThreadId;
    } ChildInfo;
    struct {
      BYTE DoNotUseThisField;
    } SuccessInfo;
    struct {
      BYTE DoNotUseThisField;
    } CrashInfo;
    struct {
      BYTE DoNotUseThisField;
    } TimeoutInfo;
    AFL_COVERAGE_PACKET CoverageInfo;
  };
};

enum CHILD_FATE {
  CHILD_UNKNOWN = -1,  // error?
  CHILD_SUCCESS = 0,
  CHILD_CRASHED,
  CHILD_TIMEOUT,
  CHILD_COVERAGE,  // new coverage
};

typedef struct _FORKSERVER_CHILD_MSG {
  DWORD pid;
  enum CHILD_FATE StatusCode;
  union {
    struct {
      uint64_t success_info;
    } SuccessInfo;
    struct {
      DWORD _exception_code;
      uint64_t ip;
      uint64_t faulting_address;
    } CrashInfo;
    struct {
      uint64_t ip;
    } CoverageInfo;
  };
} FORKSERVER_CHILD_MSG;

volatile struct AFL_COVERAGE_INFO {
  size_t NumberOfBasicBlocks;
  struct AFL_BASIC_BLOCK {
    char *ModuleName;
    uintptr_t Rva;
  } BasicBlocks[1];
};

volatile struct AFL_SETTINGS {
  uint32_t timeout;
  AFL_COVERAGE_INFO *cov_info;  // If NULL, coverage is not reported and
                                // external tracing is assumed
  BOOL enableWER;               // Enable minidumps
  BOOL debug;                   // Enable debugging
  DWORD_PTR cpuAffinityMask;  // Affinity mask for the forkserver. Never put the
                              // children on the same processor!
  char minidump_path[MAX_PATH + 1];
  char target_module_name[MAX_PATH + 1];
  char target_method[MAX_PATH + 1];
  size_t target_method_rva;
};
