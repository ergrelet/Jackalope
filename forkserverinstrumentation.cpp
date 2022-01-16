#include "forkserverinstrumentation.h"

#include <shlwapi.h>
//
#include <psapi.h>

#include "Windows/debugger.h"
#include "common.h"
#include "forkserver_interface.h"

#pragma comment(lib, "shlwapi.lib")

namespace fs = std::filesystem;

#define FORKSERVER_DLL "forkserver.dll"

#ifdef _WIN64
#define INSTRUCTION_POINTER Rip
#else
#define INSTRUCTION_POINTER Eip
#endif

typedef struct _CHILD_IDS {
  DWORD ProcessId;
  DWORD ThreadId;
} CHILD_IDS;

static std::string binary_name;

static void resume_child();
static void start_process(char *cmd);
static CHILD_IDS fork_new_child();
static int fork_run_child();
static void kill_process();
static RunResult get_child_result();

HMODULE InjectDll(HANDLE hProcess, LPCSTR szDllFilename);
DWORD get_proc_offset(char *data, char *name);
PIMAGE_NT_HEADERS map_pe_file(LPCSTR szPath, LPVOID *lpBase, HANDLE *hMapping,
                              HANDLE *hFile);
DWORD get_entry_point(LPCSTR szPath);

void WinnieForkServerInstrumentation::Init(int argc, char **argv) {
  char *option = GetOption("-target_module", argc, argv);
  if (option == nullptr) {
    FATAL("target_module argument is missing!\n");
  }
  target_module = option;

  option = GetOption("-target_method", argc, argv);
  if (option != nullptr) {
    target_method = option;
  }

  option = GetOption("-target_offset", argc, argv);
  if (option != nullptr) {
    target_offset = strtoul(option, nullptr, 0);
  }

  if (target_module[0] || target_offset || target_method[0]) {
    if ((target_module[0] == 0) ||
        ((target_offset == 0) && (target_method[0] == 0))) {
      FATAL(
          "target_module and either target_offset or target_method must be "
          "specified together\n");
    }
  }

  const char *bb_file = GetOption("-bbfile", argc, argv);
  if (bb_file == nullptr) {
    FATAL("bbfile argument is missing!\n");
  }
  bb_file_path = fs::path(bb_file);

  persist = GetBinaryOption("-persist", argc, argv, false);
  num_iterations = GetIntOption("-iterations", argc, argv, 1);
}

WinnieForkServerInstrumentation::~WinnieForkServerInstrumentation() {
  kill_process();
}

RunResult WinnieForkServerInstrumentation::Run(int argc, char **argv,
                                               uint32_t init_timeout,
                                               uint32_t timeout) {
  if (!fork_server_started) {
    if (argc > 0) {
      binary_name = argv[0];
    }

    char *cmd = ArgvToCmd(argc, argv);
    if (cmd == nullptr) {
      FATAL("ArgvToCmd failed!\n");
    }

    SpawnForkServer(cmd, timeout, init_timeout);
    free(cmd);
    fork_server_started = true;
  }

  const CHILD_IDS child_ids = fork_new_child();
  if (child_ids.ProcessId == 0) {
    return RunResult::OTHER_ERROR;
  }

  HANDLE hProcess_child =
      OpenProcess(PROCESS_ALL_ACCESS, FALSE, child_ids.ProcessId);
  if (!hProcess_child) {
    FATAL("failed to open forked process!");
  }

  if (!fork_run_child()) {
    CloseHandle(hProcess_child);
    return RunResult::OTHER_ERROR;
  }
  const auto ret_status = get_child_result();
  TerminateProcess(hProcess_child, 0);
  CloseHandle(hProcess_child);

  return ret_status;
}

RunResult WinnieForkServerInstrumentation::RunWithCrashAnalysis(
    int argc, char **argv, uint32_t init_timeout, uint32_t timeout) {
  return {};
}

void WinnieForkServerInstrumentation::CleanTarget() {}

bool WinnieForkServerInstrumentation::HasNewCoverage() { return false; }
void WinnieForkServerInstrumentation::GetCoverage(Coverage &coverage,
                                                  bool clear_coverage) {}
void WinnieForkServerInstrumentation::ClearCoverage() {}
void WinnieForkServerInstrumentation::IgnoreCoverage(Coverage &coverage) {}

uint64_t WinnieForkServerInstrumentation::GetReturnValue() { return {}; }

std::string WinnieForkServerInstrumentation::GetCrashName() { return {}; }

struct module_info_t {
  char module_name[MAX_PATH];
  int index;
  struct module_info_t *next;
};

static module_info_t *coverage_modules = NULL, *coverage_modules_tail = NULL;

// Collect coverage for this module
static module_info_t *get_coverage_module(char *module_name) {
  module_info_t *current_module = coverage_modules;
  while (current_module) {
    if (_stricmp(module_name, current_module->module_name) == 0) {
      return current_module;
    }
    current_module = current_module->next;
  }
  return NULL;
}

static volatile HANDLE child_handle, child_thread_handle;

// Fullspeed fuzzing variables
static bool child_entrypoint_reached;
static uintptr_t base_address;

static bool found_instrumentation = false;
static uint32_t total_bbs = 0;
static uint32_t visited_bbs = 0;

static LPVOID pCall_offset;
static HMODULE hModule;  // Remove base address of our injected forkserver dll
static LPVOID pFuzzer_settings,
    pForkserver_state;  // Remote address of forkserver exports
static CONTEXT lcContext;

uint64_t mem_limit{};
uint64_t cpu_aff = 1;

static volatile HANDLE hPipeChild;

DWORD WinnieForkServerInstrumentation::SpawnForkServer(char *cmd,
                                                       uint32_t timeout,
                                                       uint32_t init_timeout) {
  SpawnTargetAndInjectAgent(cmd, timeout, init_timeout);
  resume_child();
  return GetProcessId(child_handle);
}

CLIENT_ID WinnieForkServerInstrumentation::SpawnTargetAndInjectAgent(
    char *cmd, uint32_t timeout, uint32_t init_timeout) {
  // Spawn the process suspended. We can't inject immediately, however. Need to
  // let the program initialize itself before we can load a library.
  start_process(cmd);

  // Derive entrypoint address from PEB and PE header
  CONTEXT context;
  context.ContextFlags = CONTEXT_INTEGER;
  GetThreadContext(child_thread_handle, &context);
  uintptr_t pebAddr;
#ifdef _WIN64
  pebAddr = context.Rdx;
  ReadProcessMemory(child_handle, (PVOID)(pebAddr + 0x10), &base_address,
                    sizeof(base_address), NULL);
#else
  pebAddr = context.Ebx;
  ReadProcessMemory(child_handle, (PVOID)(pebAddr + 8), &base_address,
                    sizeof(base_address), NULL);
#endif
  printf("  PEB=0x%p, Base address=0x%p\n", pebAddr, base_address);

  uintptr_t oep = get_entry_point(binary_name.c_str());
  printf("  Binname: %s, OEP: %p\n", binary_name.c_str(), oep);

  uintptr_t pEntryPoint = oep + base_address;
  if (!pEntryPoint) {
    perror("GetEntryPoint");
  }
  printf("  Entrypoint = %p\n", pEntryPoint);

  // assemble infinite loop at entrypoint
  DWORD dwOldProtect;
  VirtualProtectEx(child_handle, (PVOID)pEntryPoint, 2, PAGE_EXECUTE_READWRITE,
                   &dwOldProtect);
  BYTE oepBytes[2];
  ReadProcessMemory(child_handle, (PVOID)pEntryPoint, oepBytes, 2, NULL);
  WriteProcessMemory(child_handle, (PVOID)pEntryPoint, "\xEB\xFE", 2, NULL);
  FlushInstructionCache(child_handle, (PVOID)pEntryPoint, 2);
  ResumeThread(child_thread_handle);

  // Poll the instruction pointer until it reached the entrypoint, or time out.
  for (int i = 0; context.INSTRUCTION_POINTER != pEntryPoint; Sleep(100)) {
    if (++i > 50) {
      FATAL(
          "Entrypoint trap trimed out: the forkserver injection failed, or the "
          "target process never reached its entrypoint.\n");
    }
    context.ContextFlags = CONTEXT_CONTROL;
    GetThreadContext(child_thread_handle, &context);
  }
  printf("  Entrypoint trap hit, injecting the dll now!\n");
  SuspendThread(child_thread_handle);

  // get the name of the pipe/event
  DWORD pid = GetProcessId(child_handle);
  printf("  PID is %d\n", pid);
  const auto forkserver_shm =
      std::string(FORKSERVER_SHM) + "-" + std::to_string(pid);
  printf("  Shared memory name: %s\n", forkserver_shm.c_str());
  const auto forkserver_pipe =
      std::string(FORKSERVER_PIPE) + "-" + std::to_string(pid);
  printf("  Pipe name: %s\n", forkserver_pipe.c_str());

  // Setup shared memory
  // TODO: We could do this only once for all runs, with a bit more work
  HANDLE hMapFile = CreateFileMappingA(
      INVALID_HANDLE_VALUE,  // use paging file
      nullptr,               // default security
      PAGE_READWRITE,        // read/write access
      0,                     // maximum object size (high-order DWORD)
      sizeof(AFL_SETTINGS),  // maximum object size (low-order DWORD)
      forkserver_shm.c_str());
  if (hMapFile == nullptr) {
    FATAL("Could not create file mapping object (%d).\n", GetLastError());
  }

  auto pBuf =
      (LPTSTR)MapViewOfFile(hMapFile,             // handle to map object
                            FILE_MAP_ALL_ACCESS,  // read/write permission
                            0, 0, sizeof(AFL_SETTINGS));
  if (pBuf == nullptr) {
    CloseHandle(hMapFile);
    FATAL("Could not map view of file (%d).\n", GetLastError());
  }

  AFL_SETTINGS fuzzer_settings = {0};
  fuzzer_settings.timeout = timeout;
  fuzzer_settings.cov_info = nullptr;
  fuzzer_settings.enableWER = FALSE;  // options.enable_wer;
  fuzzer_settings.cpuAffinityMask = cpu_aff;
  fuzzer_settings.debug = TRUE;               // options.debug_mode;
  strncpy(fuzzer_settings.minidump_path, "",  // options.minidump_path,
          sizeof(fuzzer_settings.minidump_path));
  strncpy(fuzzer_settings.target_module_name, target_module.c_str(),
          sizeof(fuzzer_settings.target_module_name));
  strncpy(fuzzer_settings.target_method, target_method.c_str(),
          sizeof(fuzzer_settings.target_method));
  fuzzer_settings.target_method_rva = target_offset;

  CopyMemory((PVOID)pBuf, &fuzzer_settings, sizeof(fuzzer_settings));

  // Actually inject the dll now.
  char *injectedDll = FORKSERVER_DLL;
  char szDllFilename[MAX_PATH];
  GetModuleFileNameA(NULL, szDllFilename, sizeof(szDllFilename));
  PathRemoveFileSpecA(szDllFilename);
  strncat(szDllFilename, "\\", max(0, MAX_PATH - strlen(szDllFilename) - 1));
  strncat(szDllFilename, injectedDll,
          max(0, MAX_PATH - strlen(szDllFilename) - 1));
  printf("  Injecting %s\n", szDllFilename);
  hModule = InjectDll(child_handle, szDllFilename);
  if (!hModule) {
    FATAL("InjectDll");
  }
  printf("  Forkserver dll injected, base address = %p\n", hModule);

  // Write coverage info
  // HANDLE hMapping = INVALID_HANDLE_VALUE, hFile = INVALID_HANDLE_VALUE;
  // BYTE *lpBase = NULL;
  // PIMAGE_NT_HEADERS ntHeader =
  //    map_pe_file(szDllFilename, (LPVOID *)&lpBase, &hMapping, &hFile);
  // if (!ntHeader) FATAL("Failed to parse PE header of %s", injectedDll);

  // options.preload

  // DWORD off_fuzzer_settings =
  //    get_proc_offset((char *)lpBase, "fuzzer_settings");
  // DWORD off_forkserver_state =
  //    get_proc_offset((char *)lpBase, "forkserver_state");
  // DWORD off_call_target = get_proc_offset((char *)lpBase, "call_target");

  // if (!off_fuzzer_settings || !off_call_target)
  //  FATAL("Fail to locate forkserver exports!\n");
  // printf("  fuzzer_settings offset = %08x, call_target offset = %08x\n",
  //       off_fuzzer_settings, off_call_target);

  // size_t nWritten;
  // pFuzzer_settings = (LPVOID)((uintptr_t)hModule + off_fuzzer_settings);
  // pForkserver_state = (LPVOID)((uintptr_t)hModule + off_forkserver_state);
  // pCall_offset = (LPVOID)((uintptr_t)hModule + off_call_target);
  // printf("  fuzzer_settings = %p, forkserver_state = %p, call target = %p\n",
  //       pFuzzer_settings, pForkserver_state, pCall_offset);

  // LPVOID pCovInfo;
  // LPVOID pModuleNames;
  //{
  //  size_t module_names_size;
  //  cov_modules_list module_names =
  //      serialize_coverage_modules(&module_names_size);
  //  pModuleNames = VirtualAllocEx(child_handle, NULL, module_names_size,
  //                                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  //  if (!pModuleNames) {
  //    perror("Allocating coverage modules list into child");
  //  }
  //  if (!WriteProcessMemory(child_handle, pModuleNames, module_names,
  //                          module_names_size, &nWritten) ||
  //      nWritten < module_names_size) {
  //    perror("Writing coverage modules list into child");
  //  }
  //  free(module_names);
  //}
  // size_t cov_info_size;
  // pCovInfo = nullptr;
  // AFL_COVERAGE_INFO *cov_info =
  //    serialize_breakpoints(pModuleNames, &cov_info_size);
  // pCovInfo = VirtualAllocEx(child_handle, NULL, cov_info_size,
  //                          MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  // if (!pCovInfo) {
  //  perror("Allocating basic blocks list into child");
  //}
  // if (!WriteProcessMemory(child_handle, pCovInfo, cov_info, cov_info_size,
  //                        &nWritten) ||
  //    nWritten < cov_info_size) {
  //  perror("Writing basic blocks list into child");
  //}
  // free(cov_info);

  // if (!WriteProcessMemory(child_handle, pFuzzer_settings, &fuzzer_settings,
  //                        sizeof(AFL_SETTINGS), &nWritten) ||
  //    nWritten < sizeof(AFL_SETTINGS)) {
  //  perror("Writing fuzzer settings into child");
  //}

  // if (lpBase) UnmapViewOfFile((LPCVOID)lpBase);
  // if (hMapping != INVALID_HANDLE_VALUE) CloseHandle(hMapping);
  // if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);

  // Signal to forkserver that coverage info is written
  // FORKSERVER_STATE ready = FORKSERVER_READY;
  // if (!WriteProcessMemory(child_handle, pForkserver_state, &ready,
  //                        sizeof(FORKSERVER_STATE), &nWritten) ||
  //    nWritten < sizeof(FORKSERVER_STATE)) {
  //  perror("Writing fuzzer settings into child");
  //}

  // Connect to AFL_FORKSERVER pipe.
  // Wait for forkserver to setup hooks before we resume the main thread.
  printf("Connecting to forkserver...\n");
  DWORD timeElapsed = 0;
  do {
    hPipeChild =
        CreateFileA(forkserver_pipe.c_str(), GENERIC_READ | GENERIC_WRITE, 0,
                    NULL, OPEN_EXISTING, 0, NULL);
    if (hPipeChild == INVALID_HANDLE_VALUE) {
      if (GetLastError() == ERROR_FILE_NOT_FOUND) {
        Sleep(10);
        timeElapsed += 10;
        if (timeElapsed > init_timeout) {
          FATAL("Forkserver failed to initialize!\n");
        }
        continue;
      }
      perror("CreateFileA");
    }
  } while (hPipeChild == INVALID_HANDLE_VALUE);
  DWORD dwMode = PIPE_READMODE_MESSAGE;
  if (!SetNamedPipeHandleState(hPipeChild, &dwMode, NULL, NULL)) {
    perror("SetNamedPipeHandleState");
  }
  printf("Connected to forkserver\n");
  printf("Ok, the forkserver is ready. Resuming the main thread now.\n");

  printf("Entrypoint: %p | OEP stolen bytes: %02x %02x\n", pEntryPoint,
         oepBytes[0], oepBytes[1]);

  // a possible problem is if the injected forkserver overwrites pEntryPoint
  // before we restore oepBytes. to deal with that just check that nothing
  // edited that code before we restore it.

  // fix guard page issue
  MEMORY_BASIC_INFORMATION memInfo;
  VirtualQueryEx(child_handle, (PVOID)pEntryPoint, &memInfo, sizeof(memInfo));
  if (memInfo.Protect & PAGE_GUARD) {
    VirtualProtectEx(child_handle, (PVOID)pEntryPoint, 2,
                     PAGE_EXECUTE_READWRITE, &dwOldProtect);
    printf("VirtualProtectEx : temporarily removed guard page on entrypoint\n");
  }
  WriteProcessMemory(child_handle, (PVOID)pEntryPoint, oepBytes, 2, NULL);
  FlushInstructionCache(child_handle, (PVOID)pEntryPoint, 2);
  DWORD trash;
  VirtualProtectEx(child_handle, (PVOID)pEntryPoint, 2, dwOldProtect, &trash);

  const CLIENT_ID cid{child_handle, child_thread_handle};
  return cid;
}

static void resume_child() { ResumeThread(child_thread_handle); }

static void mark_visited_breakpoint(AFL_COVERAGE_PACKET *bp) {
  // printf("Got coverage: %s+%p\n", bp->ModuleName, bp->Rva);
  // for (struct winafl_breakpoint *current = breakpoints; current;
  //     current = current->next) {
  //  if (current->rva == bp->Rva &&
  //      !strcmp(current->module->module_name, bp->ModuleName)) {
  //    // trace_printf("marking:%d\n", current->index);
  //    found_instrumentation = true;
  //    if (!current->visited) {
  //      unsigned byte_idx = current->id >> 3;
  //      if (byte_idx >= MAP_SIZE) {
  //        FATAL("Overflow");
  //      }
  //      trace_bits[byte_idx] |= 1 << (current->id & 0x7);
  //      visited_bbs++;
  //      current->visited = true;
  //    }
  //    break;
  //  }
  //}
}

// starts the forkserver process
static void start_process(char *cmd) {
  STARTUPINFOA si;
  PROCESS_INFORMATION pi;
  HANDLE hJob = NULL;
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION job_limit;

  ZeroMemory(&si, sizeof(si));
  si.cb = sizeof(si);
  ZeroMemory(&pi, sizeof(pi));

  BOOL inherit_handles = FALSE;

  hJob = CreateJobObject(NULL, NULL);
  if (hJob == NULL) {
    FATAL("CreateJobObject failed, GLE=%d.\n", GetLastError());
  }
  ZeroMemory(&job_limit, sizeof(job_limit));
  if (mem_limit || cpu_aff) {
    if (mem_limit) {
      job_limit.BasicLimitInformation.LimitFlags |=
          JOB_OBJECT_LIMIT_PROCESS_MEMORY;
      job_limit.ProcessMemoryLimit = (size_t)(mem_limit * 1024 * 1024);
    }

    if (cpu_aff) {
      job_limit.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_AFFINITY;
      job_limit.BasicLimitInformation.Affinity = (DWORD_PTR)cpu_aff;
    }
  }
  // job_limit.BasicLimitInformation.LimitFlags |=
  // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  if (!SetInformationJobObject(hJob, JobObjectExtendedLimitInformation,
                               &job_limit, sizeof(job_limit))) {
    FATAL("SetInformationJobObject failed, GLE=%d.\n", GetLastError());
  }

  DWORD dwFlags = CREATE_SUSPENDED | CREATE_NEW_CONSOLE;
  printf("  cmd: %s\n", cmd);

  // In debug mode, sinkholing stds will cause SetStdHandle in
  // ReopenStdioHandles in the forklib to fail and silently exit the child
  // process(??) So don't do that.
  if (!CreateProcessA(NULL, cmd, NULL, NULL, inherit_handles, dwFlags, NULL,
                      NULL, &si, &pi)) {
    FATAL("CreateProcess failed, GLE=%d.\n", GetLastError());
  }

  child_handle = pi.hProcess;
  // pi.hThread doesn't seem to have THREAD_ALL_ACCESS (SetThreadContext fails),
  // so Fuck that just open the thread manually.
  child_thread_handle =
      OpenThread(THREAD_ALL_ACCESS, FALSE, GetThreadId(pi.hThread));
  if (child_thread_handle == INVALID_HANDLE_VALUE) {
    perror("OpenThread");
  }
  CloseHandle(pi.hThread);

  child_entrypoint_reached = false;

  if (!AssignProcessToJobObject(hJob, child_handle)) {
    FATAL("AssignProcessToJobObject failed, GLE=%d.\n", GetLastError());
  }
  CloseHandle(hJob);
}

static CHILD_IDS fork_new_child() {
  AFL_FORKSERVER_REQUEST forkserverRequest;
  DWORD nWritten;
  forkserverRequest.Operation = AFL_CREATE_NEW_CHILD;
  if (!WriteFile(hPipeChild, &forkserverRequest, sizeof(forkserverRequest),
                 &nWritten, NULL) ||
      nWritten != sizeof(forkserverRequest)) {
    printf("Broken forkserver pipe, WriteFile");
    return {};
  }

  // get the child process info and resume the child
  AFL_FORKSERVER_RESULT forkserverResult{};
  DWORD nRead{};
  if (!ReadFile(hPipeChild, &forkserverResult, sizeof(forkserverResult), &nRead,
                NULL) ||
      nRead != sizeof(forkserverResult)) {
    printf("Broken forkserver pipe\n");
    return {};
  }
  if (forkserverResult.StatusCode != AFL_CHILD_CREATED) {
    printf("Unexpected forkserver result %d\n", forkserverResult.StatusCode);
  }
  return {forkserverResult.ChildInfo.ProcessId,
          forkserverResult.ChildInfo.ThreadId};
}

static int fork_run_child() {
  AFL_FORKSERVER_REQUEST forkserverRequest{};
  DWORD nWritten{};
  forkserverRequest.Operation = AFL_RESUME_CHILD;
  if (!WriteFile(hPipeChild, &forkserverRequest, sizeof(forkserverRequest),
                 &nWritten, NULL) ||
      nWritten != sizeof(forkserverRequest)) {
    printf("Broken forkserver pipe, failed to send forkserver request");
    return 0;
  }
  return 1;
}

static void kill_process() {
  TerminateProcess(child_handle, 0);
  WaitForSingleObject(child_handle, INFINITE);

  CancelIoEx(child_thread_handle, NULL);

  CloseHandle(hPipeChild);
  CloseHandle(child_handle);
  CloseHandle(child_thread_handle);

  child_handle = NULL;
  child_thread_handle = NULL;
  hModule = NULL;
  hPipeChild = NULL;
}

static RunResult get_child_result() {
  AFL_FORKSERVER_RESULT forkserverResult{};
  do {
    DWORD nRead{};
    if (!ReadFile(hPipeChild, &forkserverResult, sizeof(forkserverResult),
                  &nRead, NULL) ||
        nRead != sizeof(forkserverResult)) {
      printf(
          "Lost connection to the forkserver (broken pipe), failed to read "
          "forkserver result\n");
      return RunResult::OTHER_ERROR;
    }
    if (forkserverResult.StatusCode == AFL_CHILD_COVERAGE) {
      mark_visited_breakpoint(&forkserverResult.CoverageInfo);
    }
    // trace_printf("Forkserver result: %d\n", forkserverResult.StatusCode);
  } while (forkserverResult.StatusCode == AFL_CHILD_COVERAGE);

  switch (forkserverResult.StatusCode) {
    case AFL_CHILD_SUCCESS:
      return RunResult::OK;
    case AFL_CHILD_TIMEOUT:
      return RunResult::HANG;
    case AFL_CHILD_CRASHED:
      return RunResult::CRASH;
    default:
      FATAL("Unexpected forkserver result %d\n", forkserverResult.StatusCode);
  }

  // !!!! The child is now waiting on YOU to kill it! Remember to kill it!
}

// returns an array of handles for all modules loaded in the target process
DWORD get_all_modules(HANDLE child_handle, HMODULE **modules) {
  DWORD module_handle_storage_size = 1024 * sizeof(HMODULE);
  HMODULE *module_handles = (HMODULE *)malloc(module_handle_storage_size);
  DWORD hmodules_size;
  while (true) {
    if (!EnumProcessModulesEx(child_handle, module_handles,
                              module_handle_storage_size, &hmodules_size,
                              LIST_MODULES_ALL)) {
      FATAL("EnumProcessModules failed, %x\n", GetLastError());
    }
    if (hmodules_size <= module_handle_storage_size) break;
    module_handle_storage_size *= 2;
    module_handles =
        (HMODULE *)realloc(module_handles, module_handle_storage_size);
  }
  *modules = module_handles;
  // SAYF("Get all modules:%d\n", hmodules_size / sizeof(HMODULE));
  return hmodules_size / sizeof(HMODULE);
}

HMODULE FindModule(HANDLE hProcess, const char *szModuleName) {
  HMODULE *hMods;
  size_t nModules = get_all_modules(hProcess, &hMods);
  HMODULE result = NULL;
  for (unsigned int i = 0; i < nModules; i++) {
    char szModName[MAX_PATH];
    if (GetModuleFileNameExA(hProcess, hMods[i], szModName,
                             sizeof(szModName) / sizeof(char))) {
      if (!_stricmp(szModuleName, szModName)) {
        result = hMods[i];
        break;
      }
    }
  }
  free(hMods);
  return result;
}

HMODULE InjectDll(HANDLE hProcess, LPCSTR szDllFilename) {
  LPVOID pMem = VirtualAllocEx(hProcess, NULL, 4096, MEM_COMMIT | MEM_RESERVE,
                               PAGE_READWRITE);
  if (!pMem) {
    perror("VirtualAllocEx");
    return NULL;
  }
  // printf("pMem = 0x%p\n", pMem);

  BOOL bSuccess = WriteProcessMemory(hProcess, pMem, szDllFilename,
                                     strlen(szDllFilename) + 1, NULL);
  if (!bSuccess) {
    perror("WriteProcessMemory");
    return NULL;
  }
  // printf("Wrote %s\n", szDllFilename);

  LPTHREAD_START_ROUTINE pLoadLibraryA = (LPTHREAD_START_ROUTINE)GetProcAddress(
      GetModuleHandleA("kernel32"), "LoadLibraryA");
  printf("LoadLibraryA = 0x%p\n", pLoadLibraryA);
  DWORD dwThreadId;
  HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, pLoadLibraryA, pMem, 0,
                                      &dwThreadId);
  if (!hThread) {
    perror("CreateRemoteThread");
    return NULL;
  }
  // printf("Thread created, ID = %d\n", dwThreadId);

  if (WaitForSingleObject(hThread, INFINITE) == WAIT_FAILED) {
    perror("WaitForSingleObject");
    return NULL;
  }
  Sleep(100);
  // printf("Success\n");
  CloseHandle(hThread);

  return FindModule(hProcess, szDllFilename);
}

// parses PE headers and gets the module entypoint
void *get_entrypoint(HANDLE child_handle, void *base_address) {
  unsigned char headers[4096];
  size_t num_read = 0;
  if (!ReadProcessMemory(child_handle, base_address, headers, 4096,
                         &num_read) ||
      (num_read != 4096)) {
    FATAL("Error reading target memory\n");
  }
  IMAGE_DOS_HEADER *dos_header = (IMAGE_DOS_HEADER *)headers;
  DWORD pe_offset = dos_header->e_lfanew;
  IMAGE_NT_HEADERS *nt_header = (IMAGE_NT_HEADERS *)(headers + pe_offset);
  DWORD signature = nt_header->Signature;
  if (signature != IMAGE_NT_SIGNATURE) {
    FATAL("PE signature error\n");
  }
  IMAGE_OPTIONAL_HEADER *optional_header = &nt_header->OptionalHeader;
  WORD magic = optional_header->Magic;
  if ((magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) &&
      (magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)) {
    FATAL("Unknown PE magic value\n");
  }
  DWORD entrypoint_offset = optional_header->AddressOfEntryPoint;
  if (entrypoint_offset == 0) return NULL;
  return (char *)base_address + entrypoint_offset;
}

// GetProcAddress that works on another process (via parsing PE header)
DWORD get_proc_offset(char *data, char *name) {
  IMAGE_DOS_HEADER *dos_header = (IMAGE_DOS_HEADER *)data;
  DWORD pe_offset = dos_header->e_lfanew;
  IMAGE_NT_HEADERS *nt_header = (IMAGE_NT_HEADERS *)(data + pe_offset);
  DWORD signature = nt_header->Signature;
  if (signature != IMAGE_NT_SIGNATURE) {
    FATAL("PE signature error\n");
  }
  IMAGE_OPTIONAL_HEADER *optional_header = &nt_header->OptionalHeader;
  // Note: DataDirectory offset varies by PE32/PE64, so only native architecture
  // is supported
  if (optional_header->Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC) {
    FATAL("Wrong PE magic value\n");
  }

  IMAGE_EXPORT_DIRECTORY *export_table =
      (IMAGE_EXPORT_DIRECTORY
           *)(data +
              optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
                  .VirtualAddress);
  DWORD numentries = export_table->NumberOfNames;
  DWORD addresstableoffset = export_table->AddressOfFunctions;
  DWORD nameptrtableoffset = export_table->AddressOfNames;
  DWORD ordinaltableoffset = export_table->AddressOfNameOrdinals;
  DWORD *nameptrtable = (DWORD *)(data + nameptrtableoffset);
  WORD *ordinaltable = (WORD *)(data + ordinaltableoffset);
  DWORD *addresstable = (DWORD *)(data + addresstableoffset);

  DWORD i;
  for (i = 0; i < numentries; i++) {
    char *nameptr = data + nameptrtable[i];
    if (strcmp(name, nameptr) == 0) break;
  }

  if (i == numentries) return 0;

  WORD ordinal = ordinaltable[i];
  DWORD offset = addresstable[ordinal];

  return offset;
}

PIMAGE_NT_HEADERS map_pe_file(LPCSTR szPath, LPVOID *lpBase, HANDLE *hMapping,
                              HANDLE *hFile) {
  *hFile = CreateFileA(szPath, GENERIC_READ, FILE_SHARE_READ, NULL,
                       OPEN_EXISTING, 0, NULL);
  if (*hFile == INVALID_HANDLE_VALUE) {
    FATAL("Invalid handle when map PE file");
    return NULL;
  }

  *hMapping = CreateFileMappingA(
      *hFile, NULL, PAGE_READONLY | SEC_IMAGE_NO_EXECUTE, 0, 0, NULL);

  if (!*hMapping) {
    FATAL("Cannot make file mapping");
    return NULL;
  }

  *lpBase = (char *)MapViewOfFile(*hMapping, FILE_MAP_READ, 0, 0, 0);
  if (!*lpBase) {
    FATAL("Cannot make MapViewOfFile");
    return NULL;
  }

  PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)*lpBase;
  if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
    FATAL("IMAGE_DOS_SIGNATURE not matched");
    return NULL;
  }

  PIMAGE_NT_HEADERS ntHeader =
      (PIMAGE_NT_HEADERS)((uintptr_t)*lpBase + dosHeader->e_lfanew);
  if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
    FATAL("IMAGE_NT_SIGNATURE not matched");
    return NULL;
  }

  return ntHeader;
}

DWORD get_entry_point(LPCSTR szPath) {
  DWORD dwEntryPoint = 0;
  HANDLE hMapping = INVALID_HANDLE_VALUE, hFile = INVALID_HANDLE_VALUE;
  BYTE *lpBase = NULL;
  PIMAGE_NT_HEADERS ntHeader =
      map_pe_file(szPath, (LPVOID *)&lpBase, &hMapping, &hFile);
  if (ntHeader) {
    dwEntryPoint = ntHeader->OptionalHeader.AddressOfEntryPoint;
  } else {
    FATAL("Cannot parse the PEfile!");
  }

  if (lpBase) UnmapViewOfFile((LPCVOID)lpBase);
  if (hMapping != INVALID_HANDLE_VALUE) CloseHandle(hMapping);
  if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);

  return dwEntryPoint;
}

//#define BREAKPOINT_UNKNOWN 0
//#define BREAKPOINT_ENTRYPOINT 1
//#define BREAKPOINT_MODULELOADED 2
//#define BREAKPOINT_FUZZMETHOD 3
//#define BREAKPOINT_BB 4
//
// static module_info_t *add_coverage_module(char *module_name) {
//  module_info_t *module = malloc(sizeof(module_info_t));
//  if (strlen(module_name) >= sizeof(module->module_name))
//    FATAL("Module name too long: %s\n", module_name);
//  module->next = NULL;
//  strncpy(module->module_name, module_name, sizeof(module->module_name));
//  if (coverage_modules_tail) {
//    module->index = coverage_modules_tail->index + 1;
//    coverage_modules_tail->next = module;
//    coverage_modules_tail = module;
//  } else {
//    module->index = 0;
//    coverage_modules = coverage_modules_tail = module;
//  }
//  return module;
//}
//
// static void add_breakpoint(struct _module_info_t *module, uintptr_t rva,
//                           int offset, unsigned char original_opcode,
//                           int type) {
//  // printf("ADD: %x, %d, %x\n", address, offset, original_opcode);
//  struct winafl_breakpoint *new_breakpoint =
//      (struct winafl_breakpoint *)malloc(sizeof(struct winafl_breakpoint));
//
//  new_breakpoint->rva = rva;
//  new_breakpoint->file_offset = offset;
//  new_breakpoint->original_opcode = original_opcode;
//  new_breakpoint->module = module;
//  new_breakpoint->type = type;
//  new_breakpoint->visited = false;
//  new_breakpoint->id = total_bbs++;
//
//  if ((new_breakpoint->id >> 3) >= MAP_SIZE) {
//    FATAL("Too many breakpoints\n");
//  }
//
//  new_breakpoint->next = breakpoints;
//  breakpoints = new_breakpoint;
//}
//
// void load_bbs(char *bbfile) {
//  FILE *bb_fp = fopen(bbfile, "r");
//  if (!bb_fp) FATAL("Missing basic blocks file %s", bbfile);
//  fseek(bb_fp, 0, SEEK_SET);
//  char line[65535];
//  module_info_t *cur_module = NULL;
//
//  for (int i = 0; fgets(line, 1024, bb_fp); i++) {
//    if (line[0] == '[') {
//      int len = strlen(line);
//      if (line[len - 2] != ']')  // 1 for null, 1 for newline
//        FATAL("Malformed basic blocks input line: %s", line);
//      line[len - 2] = 0;
//      char *module_name = line + 1;
//      if (!(cur_module = get_coverage_module(module_name))) {
//        cur_module = add_coverage_module(module_name);
//      }
//    }
//
//    if (!cur_module)
//      FATAL(
//          "Basic blocks input file: syntax error, no module name specified: "
//          "%s\n",
//          line);
//
//    int j = 0;
//    uintptr_t rva, fo;
//    for (const char *tok = strtok(line, ","); tok && *tok;
//         tok = strtok(NULL, ",\n")) {
//      switch (j++) {
//        case 0:
//          sscanf(tok, "%p", &rva);
//          break;
//        case 1:
//          sscanf(tok, "%p", &fo);
//          add_breakpoint(cur_module, rva, fo, 0, BREAKPOINT_BB);
//          break;
//        default:
//          FATAL("Malformed basic blocks input line: %s\n", tok);
//      }
//    }
//  }
//
//  fclose(bb_fp);
//
//  if (!coverage_modules_tail) {
//    FATAL("No coverage modules specified in basic blocks file\n");
//  }
//}
