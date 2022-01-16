#include <Windows.h>
#include <forklib.h>

#include <cstdio>
#include <mutex>
#include <string>
#include <unordered_map>

#include "forkserver_interface.h"

#ifdef _WIN64
#define INSTRUCTION_POINTER Rip
#define TRAMPOLINE_SIZE 14
#define THUNK_SIZE 16
#else
#define INSTRUCTION_POINTER Eip
#define TRAMPOLINE_SIZE 5
#define THUNK_SIZE 5
#endif

#define fuzzer_printf(...) fprintf(fuzzer_stdout, ##__VA_ARGS__##);

// Print if debug enabled
#define debug_printf(...)                    \
  { /*if (fuzzer_settings.debug)*/           \
    fprintf(fuzzer_stdout, ##__VA_ARGS__##); \
  }

// For non-user facing debug messages (for fuzzer developers' eyes)
#if (!_DEBUG)
#define trace_printf(fmt, ...) (0)
#else
#define trace_printf(fmt, ...) \
  fprintf(fuzzer_stdout, "TRACE: " fmt, ##__VA_ARGS__##)
#endif

#define FATAL(f, ...)                                                    \
  {                                                                      \
    fprintf(fuzzer_stdout, f ": %d\n", ##__VA_ARGS__##, GetLastError()); \
    fprintf(fuzzer_stdout, "Press enter to exit\n");                     \
    fflush(fuzzer_stdout);                                               \
    (void)getc(fuzzer_stdin);                                            \
    suicide();                                                           \
  }

struct BreakpointInfo {
  BYTE original_byte;
  HMODULE h_module;
};

[[noreturn]] void bye();
[[noreturn]] void suicide();

static FILE *fuzzer_stdout, *fuzzer_stdin;
static std::string forkserver_child_pipe;
static AFL_SETTINGS fuzzer_settings;
static BYTE *target_address;
static HANDLE hPipeAfl;
static std::unordered_map<LPVOID, BreakpointInfo> breakpoints;
static std::mutex breakpoints_mutex;
static SYSTEM_INFO g_sys_info;
static PVOID g_GlobalExceptionHandler;
static PVOID g_TemporaryExceptionHandler;
static BYTE targetOriginalBytes[TRAMPOLINE_SIZE] = {
    0};  // stolen bytes from hooking the target address

static LPVOID pTerminateProcess = NULL;
static LPVOID pRtlExitUserProcess = NULL;

// DO NOT PUT ME IN TLS OR I WILL SEGFAULT ON USE IN THE HANDLER!
// 0 = none
// 1 = NtCreateFile
// 2 = TerminateProcess
static int singleStep = 0;
static LONG handlerReentrancy =
    0;  // Detect if our breakpoint handler itself is faulty
static DWORD childCpuAffinityMask;

// Forkserver parent-child ipc
static OVERLAPPED oChildPipe;
static HANDLE hPipeChild;
static HANDLE waitHandles[2] = {NULL, NULL};

void SetupServer();
[[noteturn]] void forkserver();
void SetupChildPipe();
[[noreturn]] void do_child();
PROCESS_INFORMATION do_fork();
CHILD_FATE do_parent(PROCESS_INFORMATION pi);
void parent_report_coverage(uintptr_t ip, BreakpointInfo bp);
[[noreturn]] void call_target();
void SetupExceptionFilter();
LONG WINAPI GlobalExceptionHandler(EXCEPTION_POINTERS *ExceptionInfo);
LONG WINAPI TemporaryExceptionHandler(EXCEPTION_POINTERS *ExceptionInfo);
LONG WINAPI ChildBreakpointHandler(EXCEPTION_POINTERS *ExceptionInfo);
LONG WINAPI ChildCrashHandler(EXCEPTION_POINTERS *ExceptionInfo);
BreakpointInfo RestoreBreakpoint(LPVOID target);
BOOL DoesBreakpointExists(LPVOID target);
void hook_TerminateProcess();
void hook_RtlExitUserProcess();
const char *get_module_filename(HMODULE hModule);
void PatchCode(LPVOID target, _In_ const BYTE *bytes, _In_ size_t len,
               _Out_opt_ BYTE *stolenBytes);

DWORD CALLBACK cbThreadStart(LPVOID hModule) {
  // Create a console for printf
  AllocConsole();
  fuzzer_stdout = fopen("CONOUT$", "w+");
  fuzzer_stdin = fopen("CONIN$", "r");
  setvbuf(fuzzer_stdout, NULL, _IONBF, 0);
  setvbuf(fuzzer_stdin, NULL, _IONBF, 0);
  SetConsoleTitleA("Winnie -- Forkserver");

  // Get the name of pipe/event
  DWORD pid = GetCurrentProcessId();
  fuzzer_printf("Forkserver PID: %d\n", pid);
  const auto forkserver_shm =
      std::string(FORKSERVER_SHM) + "-" + std::to_string(pid);
  printf("  Shared memory name: %s\n", forkserver_shm.c_str());
  const auto forkserver_pipe =
      std::string(FORKSERVER_PIPE) + "-" + std::to_string(pid);
  printf("  Pipe name: %s\n", forkserver_pipe.c_str());

  // Retrieve settings from shared memory
  HANDLE hMapFile =
      OpenFileMapping(FILE_MAP_ALL_ACCESS,      // read/write access
                      FALSE,                    // do not inherit the name
                      forkserver_shm.c_str());  // name of mapping object

  if (hMapFile == nullptr) {
    FATAL("Could not open file mapping object (%d).\n", GetLastError());
  }

  auto pBuf =
      (LPTSTR)MapViewOfFile(hMapFile,             // handle to map object
                            FILE_MAP_ALL_ACCESS,  // read/write permission
                            0, 0, sizeof(fuzzer_settings));
  if (pBuf == nullptr) {
    CloseHandle(hMapFile);
    FATAL("Could not map view of file (%d).\n", GetLastError());
  }

  GetSystemInfo(&g_sys_info);
  const DWORD cpu_core_count = g_sys_info.dwNumberOfProcessors;

  CopyMemory(&fuzzer_settings, pBuf, sizeof(fuzzer_settings));
  forkserver_child_pipe =
      std::string(FORKSERVER_CHILD_PIPE) + "-" + std::to_string(pid);
  childCpuAffinityMask =
      ~fuzzer_settings.cpuAffinityMask & ((1ULL << cpu_core_count) - 1ULL);

  fuzzer_printf("Timeout: %dms\n", fuzzer_settings.timeout);
  fuzzer_printf("Minidumps (WER): %s\n",
                fuzzer_settings.enableWER ? "enabled" : "disabled");
  fuzzer_printf("Processor affinity: 0x%llx (%d cores)\n",
                fuzzer_settings.cpuAffinityMask, cpu_core_count);
  if (fuzzer_settings.enableWER) {
    fuzzer_printf("Will look for minidumps in %s\n",
                  fuzzer_settings.minidump_path);
  }

  if (!SetProcessAffinityMask(GetCurrentProcess(),
                              fuzzer_settings.cpuAffinityMask)) {
    FATAL("Failed to set process affinity");
  }

  const auto module_handle =
      GetModuleHandleA(fuzzer_settings.target_module_name);
  if (module_handle == nullptr) {
    FATAL("Failed to find target module");
  }

  if (strlen(fuzzer_settings.target_method) > 0) {
    target_address =
        (BYTE *)GetProcAddress(module_handle, fuzzer_settings.target_method);
    fuzzer_printf(
        "Target module: '%s' | Target method: '%s' |  Target address: 0x%p\n",
        fuzzer_settings.target_module_name, fuzzer_settings.target_method,
        target_address);
  } else if (fuzzer_settings.target_method_rva != 0) {
    target_address = (BYTE *)module_handle + fuzzer_settings.target_method_rva;
    fuzzer_printf("Target module: '%s' | Target address: 0x%p\n",
                  fuzzer_settings.target_module_name, target_address);
  } else {
    FATAL("Target method not configured properly");
  }

  // Get TerminateProcess address
  pTerminateProcess = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"),
                                             "TerminateProcess");
  pRtlExitUserProcess = (LPVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"),
                                               "RtlExitUserProcess");

  // Hook the target address via guard page
  MEMORY_BASIC_INFORMATION targetPageInfo;
  DWORD dwOldProtect;
  VirtualQuery(target_address, &targetPageInfo, sizeof(targetPageInfo));
  VirtualProtect(target_address, 1, targetPageInfo.Protect | PAGE_GUARD,
                 &dwOldProtect);

  g_GlobalExceptionHandler =
      AddVectoredExceptionHandler(TRUE, GlobalExceptionHandler);

  hPipeAfl =
      CreateNamedPipeA(forkserver_pipe.c_str(),
                       PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                       PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, 1,
                       4096, 4096, 0, NULL);
  if (hPipeAfl == INVALID_HANDLE_VALUE) {
    FATAL("CreateNamedPipe");
  }

  fuzzer_printf("Connecting to AFL and returning control to main binary!\n");
  fflush(fuzzer_stdout);

  if (!ConnectNamedPipe(hPipeAfl, NULL) &&
      GetLastError() != ERROR_PIPE_CONNECTED)  // This will block!
  {
    FATAL("ConnectNamedPipe");
  }

  return 0;
}

extern "C" [[noreturn]] void harness_main() {
  fuzzer_printf("Target hook reached!\n");
  // fuzzer_printf("Unhooking early critical functions...\n");
  // InlineUnhook(pNtProtectVirtualMemory, pOrgNtProtectVirtualMemory,
  // THUNK_SIZE); InlineUnhook(pRtlAddVectoredExceptionHandler,
  //             pOrgRtlAddVectoredExceptionHandler, THUNK_SIZE);
  fuzzer_printf("-> OK!\n");

  // Setup a temporary handler because a breakpoint might get tripped while we
  // are setting up!!!
  RemoveVectoredExceptionHandler(g_GlobalExceptionHandler);
  g_GlobalExceptionHandler = INVALID_HANDLE_VALUE;
  g_TemporaryExceptionHandler =
      AddVectoredExceptionHandler(TRUE, TemporaryExceptionHandler);

  // TODO
  // install_breakpoints();
  // Restore target hook stolen bytes
  PatchCode(target_address, targetOriginalBytes, TRAMPOLINE_SIZE, NULL);

  SetupServer();

  // if (harness_info->setup_func) {
  //  harness_info->setup_func();
  //}

  forkserver();  // noreturn
  // if (fuzzer_settings.mode == DRYRUN) {
  //  SetupTarget();
  //  call_target();  // noreturn
  //} else if (fuzzer_settings.mode == PERSISTENT) {
  //  SetupTarget();
  //  persistent_server();  // noreturn
  //} else if (fuzzer_settings.mode == FORK) {
  //  forkserver();  // noreturn
  //} else {
  //  FATAL("Invalid fuzzer mode");
  //}
}

void SetupServer() {
  if (fuzzer_settings.enableWER) {
    // enable WER (Windows Error Reporting) so we can monitor crash dumps
    SetErrorMode(0);
  } else {
    // disable WER since minidumps are slow
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
  }

  if (!fuzzer_settings.debug) {
    // Kill the target stdio handles
    freopen("nul", "w+", stdout);
    freopen("nul", "w+", stderr);
    freopen("nul", "r", stdin);
    HANDLE devnul_handle = CreateFileA("nul", GENERIC_READ | GENERIC_WRITE,
                                       FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                                       OPEN_EXISTING, 0, NULL);
    if (devnul_handle == INVALID_HANDLE_VALUE) {
      FATAL("Unable to open the nul device.");
    }
    SetStdHandle(STD_INPUT_HANDLE, devnul_handle);
    SetStdHandle(STD_OUTPUT_HANDLE, devnul_handle);
    SetStdHandle(STD_ERROR_HANDLE, devnul_handle);
  }
}

[[noteturn]] void forkserver() {
  SetupChildPipe();

  fuzzer_printf("Okay, spinning up the forkserver now.\n");

  // forkserver
  int forkCount = 0;
  int done = false;
  PROCESS_INFORMATION curChildInfo = {0};
  int childPending = 0;
  while (!done) {
    AFL_FORKSERVER_REQUEST aflRequest;
    DWORD nRead;
    if (!ReadFile(hPipeAfl, &aflRequest, sizeof(aflRequest), &nRead, NULL) ||
        nRead != sizeof(aflRequest)) {
      FATAL("Broken AFL pipe, ReadFile (forkserver)");
    }
    switch (aflRequest.Operation) {
      case AFL_CREATE_NEW_CHILD: {
        trace_printf("Fuzzer asked me to create new child\n");
        if (childPending) {
          FATAL(
              "Invalid request; a forked child is already standby for "
              "execution");
        }
        forkCount++;
        curChildInfo = do_fork();
        AFL_FORKSERVER_RESULT aflResponse{};
        aflResponse.StatusCode = AFL_CHILD_CREATED;
        aflResponse.ChildInfo.ProcessId = curChildInfo.dwProcessId;
        aflResponse.ChildInfo.ThreadId = curChildInfo.dwThreadId;
        DWORD nWritten{};
        if (!WriteFile(hPipeAfl, &aflResponse, sizeof(aflResponse), &nWritten,
                       NULL) ||
            nWritten != sizeof(aflResponse)) {
          FATAL("Broken AFL pipe, WriteFile");
        }
        childPending = 1;
        break;
      }
      case AFL_RESUME_CHILD: {
        if (!childPending) {
          FATAL("Invalid request; no forked child to resume");
        }
        trace_printf("Fuzzer asked me to resume the child\n");
        // Wait for the forked child to suspend itself, then we will resume it.
        // (In order to synchronize)
        while (1) {
          DWORD exitCode = 0;
          // If the fork fails somehow, the child will unexpectedly die without
          // suspending itself.
          if (!GetExitCodeProcess(curChildInfo.hProcess, &exitCode) ||
              exitCode != STILL_ACTIVE) {
            fuzzer_printf(
                "The forked child died before we resumed it! Exit code: %d\n",
                exitCode);
            suicide();
          }
          DWORD dwWaitResult = WaitForSingleObject(curChildInfo.hThread, 0);
          if (dwWaitResult ==
              WAIT_OBJECT_0) {  // Thread object is signaled -- thread died
            fuzzer_printf(
                "The forked child thread died before we resumed it!\n");
            suicide();
          }
          DWORD dwResult = ResumeThread(curChildInfo.hThread);
          if (dwResult == (DWORD)-1) FATAL("Failed to resume the child");
          if (dwResult == 0) {  // Hasn't suspended itself yet
            Sleep(1);
            continue;
          } else if (dwResult == 1)
            break;
          else
            FATAL("Unexpected suspend count %d", dwResult);
        }
        AFL_FORKSERVER_RESULT aflResponse;
        CHILD_FATE childStatus =
            do_parent(curChildInfo);  // return child's status from parent.
        CloseHandle(curChildInfo.hProcess);
        CloseHandle(curChildInfo.hThread);
        RtlZeroMemory(&curChildInfo, sizeof(curChildInfo));
        switch (childStatus) {
          case CHILD_SUCCESS:
            aflResponse.StatusCode = AFL_CHILD_SUCCESS;
            break;
          case CHILD_CRASHED:
            aflResponse.StatusCode = AFL_CHILD_CRASHED;
            break;
          case CHILD_TIMEOUT:
            aflResponse.StatusCode = AFL_CHILD_TIMEOUT;
            break;
          default:
            FATAL("Child exited in an unexpected way?");
        }
        DWORD nWritten;
        if (!WriteFile(hPipeAfl, &aflResponse, sizeof(aflResponse), &nWritten,
                       NULL) ||
            nWritten != sizeof(aflResponse)) {
          FATAL("Broken AFL pipe, WriteFile");
        }
        childPending = 0;
        break;
      }
      case AFL_TERMINATE_FORKSERVER:
        debug_printf("Fuzzer asked me to kill the forkserver\n");
        done = true;
        break;
    }
  }

  DisconnectNamedPipe(hPipeChild);
  DisconnectNamedPipe(hPipeAfl);
  CloseHandle(hPipeAfl);
  CloseHandle(hPipeChild);
  fuzzer_printf("Bye.\n");
  suicide();
}

void SetupChildPipe() {
  HANDLE hConnectEvent = CreateEvent(NULL, TRUE, TRUE, NULL);
  RtlZeroMemory(&oChildPipe, sizeof(oChildPipe));
  oChildPipe.hEvent = hConnectEvent;
  hPipeChild = CreateNamedPipeA(
      forkserver_child_pipe.c_str(),
      PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
      PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, 1, 4096, 4096, 0,
      NULL);
  if (hPipeChild == INVALID_HANDLE_VALUE) {
    FATAL("CreateNamedPipe");
  }
  if (ConnectNamedPipe(hPipeChild, &oChildPipe)) {
    FATAL("ConnectNamedPipe");
  }
  waitHandles[0] = oChildPipe.hEvent;
}

void SetupTarget();

[[noreturn]] void do_child() {
  //#ifdef _DEBUG
  //  fuzzer_stdout = fopen("CONOUT$", "w+");
  //  fuzzer_stdin = fopen("CONIN$", "r");
  //  setvbuf(fuzzer_stdout, NULL, _IONBF, 0);
  //  setvbuf(fuzzer_stdin, NULL, _IONBF, 0);
  //#endif

  // trace_printf("I am the child.\n");
  // trace_printf("target address = %p\n", target_address);
  SuspendThread(GetCurrentThread());  // wait for parent to unsuspend us when
                                      // AFL gives the message
  SetupTarget();
  call_target();  // does not return
}

void SetupTarget() {
  SetupExceptionFilter();

  // Patch NtCreateFile
  // hook_NtCreateFile();
  hook_TerminateProcess();
  hook_RtlExitUserProcess();
}

void SetupExceptionFilter() {
  // for our breakpoints
  AddVectoredExceptionHandler(TRUE, ChildBreakpointHandler);

  // remove temporary handler
  RemoveVectoredExceptionHandler(g_TemporaryExceptionHandler);

  // crash reporting to forkserver parent
  SetUnhandledExceptionFilter(ChildCrashHandler);

  // apparently, this exception handler runs even when the
  // UnhandledExceptionFilter doesn't. it's the ULTIMATE exception handler!
  // preempts WER even!
  // AddVectoredContinueHandler(FALSE, ChildCrashHandler);

  // Don't let other people mess with our exception handler.
#ifdef _WIN64
  uint8_t ret[] = {0xc3};  // ret
#else
  uint8_t ret[] = {0xc2, 0x04, 0x00};  // ret 4
#endif
  PatchCode(SetUnhandledExceptionFilter, ret, sizeof(ret), NULL);
}

PROCESS_INFORMATION do_fork() {
  // spawn new child with fork
  PROCESS_INFORMATION pi;
  DWORD pid = fork(&pi);
  if (pid == -1) {
    FATAL("fork failed\n");
  } else if (!pid)  // child (pid = 0)
  {
    do_child();  // does not return
  }

  // VERY IMPORTANT for performance.
  if (!SetProcessAffinityMask(GetCurrentProcess(), childCpuAffinityMask)) {
    FATAL("Failed to set process affinity");
  }

  // Parent report child's return status
  debug_printf("Child pid: %d\n", pid);

  return pi;
}

BOOL AcceptPipe(FORKSERVER_CHILD_MSG *msg, DWORD *lpReadSize);

CHILD_FATE do_parent(PROCESS_INFORMATION pi) {
  waitHandles[1] = pi.hProcess;
  CHILD_FATE childStatus;
  do {
    childStatus = CHILD_UNKNOWN;
    switch (WaitForMultipleObjects(ARRAYSIZE(waitHandles), waitHandles, FALSE,
                                   fuzzer_settings.timeout)) {
      case WAIT_OBJECT_0: {  // waitHandles[0] = oChildPipe.hEvent;
        trace_printf("Child event is alerted\n");
        FORKSERVER_CHILD_MSG msg;
        DWORD nRead;

        if (!AcceptPipe(&msg, &nRead)) {
          FATAL("Failed to communicate with child process!\n");
          break;
        }

        if (msg.StatusCode == CHILD_COVERAGE) {
          debug_printf("Child has new coverage: %llx\n", msg.CoverageInfo.ip);

          // remove the breakpoint.
          BreakpointInfo bp = RestoreBreakpoint((LPVOID)msg.CoverageInfo.ip);

          // report to fuzzer
          parent_report_coverage((uintptr_t)msg.CoverageInfo.ip, bp);
        } else {
          debug_printf("Child result: %d\n", msg.StatusCode);
        }
        childStatus = msg.StatusCode;
        break;
      }
      case WAIT_OBJECT_0 + 1:  // waitHandles[1] = pi.hProcess;
        debug_printf("Child process died unexpectedly (crash)\n");
        childStatus = CHILD_CRASHED;
        break;
      case WAIT_TIMEOUT:
        debug_printf("Child timed out\n");
        childStatus = CHILD_TIMEOUT;
        TerminateProcess(pi.hProcess, 1);
        break;
      default:
        FATAL("WaitForMultipleObjects failed");
    }
  } while (childStatus == CHILD_COVERAGE);

  if (childStatus == CHILD_UNKNOWN) {
    fuzzer_printf("Child status unknown (crash?)\n");
    // If minidump found, the child actually crashed violently (stack BOF, bad
    // IP)
    // if (SearchForMinidump(pi.dwProcessId)) {
    //  fuzzer_printf("We found a minidump. This is a serious crash.\n");
    //  childStatus = CHILD_CRASHED;
    //}
  }

  debug_printf("Child fate: %d\n", childStatus);
  return childStatus;
}

// Communicate child results.
BOOL AcceptPipe(FORKSERVER_CHILD_MSG *msg, DWORD *lpReadSize) {
  BYTE response[1] = {0};
  BOOL success = FALSE;

  if (!GetOverlappedResult(hPipeChild, &oChildPipe, lpReadSize, TRUE)) {
    fuzzer_printf("GetOverlappedResult failed %d\n", GetLastError());
    goto cleanup;
  }
  trace_printf("Pipe connected\n");

  if (!ReadFile(hPipeChild, msg, sizeof(FORKSERVER_CHILD_MSG), NULL,
                &oChildPipe) &&
      GetLastError() != ERROR_IO_PENDING) {
    fuzzer_printf("ReadFile failed: %d\n", GetLastError());
    goto cleanup;
  }
  if (!GetOverlappedResult(hPipeChild, &oChildPipe, lpReadSize, TRUE)) {
    fuzzer_printf("Read error %d\n", GetLastError());
    goto cleanup;
  }
  trace_printf("Rx done.\n");

  if (!WriteFile(hPipeChild, response, sizeof(response), NULL, &oChildPipe) &&
      GetLastError() != ERROR_IO_PENDING) {
    fuzzer_printf("WriteFile failed: %d\n", GetLastError());
    goto cleanup;
  }
  DWORD nWritten;
  if (!GetOverlappedResult(hPipeChild, &oChildPipe, &nWritten, TRUE)) {
    fuzzer_printf("Write error: %d\n", GetLastError());
    goto cleanup;
  }
  trace_printf("Tx done.\n");

  success = TRUE;

cleanup:
  DisconnectNamedPipe(hPipeChild);
  trace_printf("Disconnected.\n");

  if (ConnectNamedPipe(hPipeChild, &oChildPipe)) {
    FATAL("ConnectNamedPipe");
  } else if (GetLastError() == ERROR_PIPE_CONNECTED) {
    // This can happen if client connected already.
    // Need to alert event waiters to accept connection and prevent hang.
    SetEvent(oChildPipe.hEvent);
  } else if (GetLastError() != ERROR_IO_PENDING) {
    FATAL("ConnectNamedPipe");
  }

  return success;
}

void parent_report_coverage(uintptr_t ip, BreakpointInfo bp) {
  DWORD nWritten{};
  AFL_FORKSERVER_RESULT aflResponse{};
  aflResponse.StatusCode = AFL_CHILD_COVERAGE;
  aflResponse.CoverageInfo.Rva = ip - (uintptr_t)bp.h_module;
  strncpy(aflResponse.CoverageInfo.ModuleName, get_module_filename(bp.h_module),
          sizeof(aflResponse.CoverageInfo.ModuleName));
  debug_printf("* %s+%p\n", aflResponse.CoverageInfo.ModuleName,
               aflResponse.CoverageInfo.Rva);
  if (!WriteFile(hPipeAfl, &aflResponse, sizeof(aflResponse), &nWritten,
                 NULL) ||
      nWritten != sizeof(aflResponse)) {
    FATAL("Broken AFL pipe, WriteFile");
  }
}

extern "C" [[noreturn]] void report_end();

#ifdef _WIN64
extern "C" {
CONTEXT savedContext;
void FuzzingHarness(void);
}

[[noreturn]] void call_target() {
  savedContext.Rip = (DWORD64)target_address;
  RtlRestoreContext(&savedContext, NULL);
  // the return address SHOULD be report_end
}

#else
uintptr_t savedEsp;
uint32_t savedregsEsp;
#define HARNESS_STACK_SIZE 0x40
__declspec(align(16)) uint8_t harnessStack[HARNESS_STACK_SIZE];
__declspec(align(64)) BYTE xsaveData[4096];

[[noreturn]] void call_target() {
  _asm {
    // context switch to target.
		xor eax, eax;
		not eax;
		mov edx, eax;
		lea ecx, [xsaveData];
		xrstor[ecx];
		mov esp, [savedregsEsp];
		popfd;
		popad;
		mov esp, [savedEsp];

    // now in target context.
		call [fuzz_iter_address];

    // ANYTHING we do must be inside a new function as we have no longer have a
    // stack frame.
		jmp [report_end];
  }
}

__declspec(naked) void FuzzingHarness(void) {
  _asm {
    // context switch to harness, first saving the context of target
		add esp, 4;  // discard return address
		mov[savedEsp], esp;
		lea esp, [harnessStack + HARNESS_STACK_SIZE];
		pushad;
		pushfd;
		mov[savedregsEsp], esp;
		mov esp, [savedEsp];  // Stack pivot fucks up GetModuleHandleA ???
		sub esp, 0x1000;  // Let's allocate some space... to just lubricate some
                      // things. Makes SetUnhandledExceptionHandler work(?)
		xor eax, eax;
		not eax;
		mov edx, eax;
		lea ecx, [xsaveData];
		xsave[ecx];
                      // now we're in the harness context.
		jmp harness_main;
      }
}
#endif

[[noreturn]] void report_end() {
  // ipc to the forkserver to tell him we finished.
  FORKSERVER_CHILD_MSG message;
  message.StatusCode = CHILD_SUCCESS;
  DWORD nRead;
  BYTE response[1] = {};
  // Unhook NtCreateFile before CallNamedPipe
  // RestoreBreakpoint(pCreateFile);
  BOOL result =
      CallNamedPipeA(forkserver_child_pipe.c_str(), &message, sizeof(message),
                     response, sizeof(response), &nRead, NMPWAIT_WAIT_FOREVER);
  // trace_printf("Okay, goodbye.\n");
  // getc(fuzzer_stdin);
  bye();
}

void report_crashed(DWORD _exception_code, uint64_t ip,
                    uint64_t faulting_address) {
  FORKSERVER_CHILD_MSG message;
  message.pid = GetCurrentProcessId();
  message.StatusCode = CHILD_CRASHED;
  message.CrashInfo._exception_code = _exception_code;
  message.CrashInfo.ip = ip;
  message.CrashInfo.faulting_address = faulting_address;
  DWORD nRead;
  BYTE response[1] = {};
  // Unhook NtCreateFile before CallNamedPipe
  // RestoreBreakpoint(pCreateFile);
  BOOL result =
      CallNamedPipeA(forkserver_child_pipe.c_str(), &message, sizeof(message),
                     response, sizeof(response), &nRead, NMPWAIT_WAIT_FOREVER);
}

void child_report_coverage(uintptr_t ip, BreakpointInfo bp) {
  FORKSERVER_CHILD_MSG message;
  message.pid = GetCurrentProcessId();
  message.StatusCode = CHILD_COVERAGE;
  message.CoverageInfo.ip = ip;
  DWORD nRead;
  BYTE response[1] = {};
  // Unhook NtCreateFile before CallNamedPipe
  // RestoreBreakpoint(pCreateFile);
  BOOL result =
      CallNamedPipeA(forkserver_child_pipe.c_str(), &message, sizeof(message),
                     response, sizeof(response), &nRead, NMPWAIT_WAIT_FOREVER);
  // hook_NtCreateFile();  // Rehook NtCreateFile
}

void GuardTargetAddr() {
  DWORD dwOldProtect{};
  MEMORY_BASIC_INFORMATION targetPageInfo{};
  if (VirtualQuery(target_address, &targetPageInfo, sizeof(targetPageInfo))) {
    VirtualProtect(target_address, 1, targetPageInfo.Protect | PAGE_GUARD,
                   &dwOldProtect);
  }
}

// Assembles a far jump to dest.
void AssembleTrampoline(BYTE *dst, uintptr_t target,
                        _Out_opt_ BYTE *stolenBytes) {
#ifdef _WIN64
  BYTE trampoline[TRAMPOLINE_SIZE] = {
      0x68, 0x00, 0x00, 0x00, 0x00,  // push qword XXXXXXXX
      0xC7, 0x44, 0x24, 0x04, 0x00,
      0x00, 0x00, 0x00,  // mov dword ptr [rsp+4], XXXXXXXX
      0xC3               // ret
  };
  DWORD64 jmpTarget = (DWORD64)target;
  *(DWORD *)(trampoline + 1) = (DWORD)(jmpTarget & 0xFFFFFFFF);
  *(DWORD *)(trampoline + 9) = (DWORD)((jmpTarget >> 32) & 0xFFFFFFFF);
#else
  BYTE trampoline[TRAMPOLINE_SIZE] = {
      0xE9, 0x00, 0x00, 0x00, 0x00,  // jmp XXXXXXXX
  };
  *(DWORD *)(trampoline + 1) = (DWORD)(target - ((uintptr_t)dst + 5));
#endif
  PatchCode(dst, trampoline, TRAMPOLINE_SIZE, stolenBytes);
}

void CreateFile_hook(EXCEPTION_POINTERS *ExceptionInfo) {
  const wchar_t *input_name = L".cur_input";
  // if (harness_info->input_file) input_name = harness_info->input_file;

#ifdef _WIN64
  DWORD64 r8 = ExceptionInfo->ContextRecord->R8;
  // See if the file name contains .cur_input
  POBJECT_ATTRIBUTES obj = (POBJECT_ATTRIBUTES)r8;
  PUNICODE_STRING testStr = (PUNICODE_STRING)obj->ObjectName;
  std::wstring wStrBuf(testStr->Buffer, testStr->Length / sizeof(WCHAR));
  const wchar_t *wStr = wStrBuf.c_str();
  debug_printf("Filename = %ls\n", wStr);
  if (wcsstr(wStr, input_name)) {
    // overwrite buffer
    debug_printf(
        "Intercepted NtCreateFile on input file; overwrite share flag\n");
    DWORD shared_flag = FILE_SHARE_READ | FILE_SHARE_WRITE;
    *(DWORD64 *)(r8 + (sizeof(DWORD) * 7)) |= shared_flag;
  }
#else
  DWORD esp = ExceptionInfo->ContextRecord->Esp;
  uintptr_t buffer[10];
  memcpy(buffer, (LPVOID)(esp + sizeof(void *)), sizeof(buffer));

  // See if the file name contains .cur_input
  // trace_printf("Current shared flag: %x\n", *(buffer + 6));
  POBJECT_ATTRIBUTES obj = (POBJECT_ATTRIBUTES) * (buffer + 2);
  PUNICODE_STRING testStr = (PUNICODE_STRING)obj->ObjectName;
  std::wstring wStrBuf(testStr->Buffer, testStr->Length / sizeof(WCHAR));
  const wchar_t *wStr = wStrBuf.c_str();
  debug_printf("Filename = %ls\n", wStr);
  if (wcsstr(wStr, input_name)) {
    // overwrite buffer
    debug_printf(
        "We found NtCreateFile with .cur_input, we will overwrite share "
        "flag\n");
    DWORD shared_flag = FILE_SHARE_READ | FILE_SHARE_WRITE;
    *(DWORD *)(esp + (sizeof(DWORD) * 7)) |= shared_flag;
  }
#endif
}

void TerminateProcess_hook(EXCEPTION_POINTERS *ExceptionInfo) {
#ifdef _WIN64
  HANDLE hProcess = (HANDLE)ExceptionInfo->ContextRecord->Rcx;
#else
  DWORD esp = ExceptionInfo->ContextRecord->Esp;
  HANDLE hProcess = *(HANDLE *)(esp + 4);
#endif
  if (GetCurrentProcess() == hProcess ||
      GetCurrentProcessId() == GetProcessId(hProcess)) {
    // trace_printf("Exit5 %d\n", handlerReentrancy);
    InterlockedDecrement(&handlerReentrancy);
    if (handlerReentrancy != 0)
      FATAL("Bad re-entry count %d?", handlerReentrancy);
    report_end();
  }
}

LONG WINAPI GlobalExceptionHandler(EXCEPTION_POINTERS *ExceptionInfo) {
  if (singleStep) {
    if (ExceptionInfo->ExceptionRecord->ExceptionCode !=
        EXCEPTION_SINGLE_STEP) {
      fuzzer_printf(
          "Expecting single step trap but instead received exception %08x!!! "
          "Likely the breakpoint handler is faulty!!",
          ExceptionInfo->ExceptionRecord->ExceptionCode);
    }

    debug_printf("single stepped, reapply the guard page\n");
    GuardTargetAddr();

    singleStep = 0;

    return EXCEPTION_CONTINUE_EXECUTION;
  }

  if (ExceptionInfo->ExceptionRecord->ExceptionCode ==
      STATUS_GUARD_PAGE_VIOLATION) {
    debug_printf("GUARD_PAGE - ExceptionAddress=%p ExceptionInformation=%p\n",
                 ExceptionInfo->ExceptionRecord->ExceptionAddress,
                 ExceptionInfo->ExceptionRecord->ExceptionInformation[1]);

    uintptr_t fault_addr =
        (uintptr_t)ExceptionInfo->ExceptionRecord->ExceptionAddress;
    uintptr_t page_start = fault_addr - (fault_addr % g_sys_info.dwPageSize);
    uintptr_t page_end = page_start + g_sys_info.dwPageSize;
    uintptr_t ip = ExceptionInfo->ContextRecord->INSTRUCTION_POINTER;

    // we guess that it's unpacked if we're executing code in the same page as
    // our target address.
    if (page_start <= (uintptr_t)target_address &&
        (uintptr_t)target_address < page_end && page_start <= ip &&
        ip < page_end) {
      debug_printf("unpacked?\n");
      // we can't assemble a full trampoline right away, because the target
      // address may be a 5-byte thunk. since the 64-bit trampoline is bigger
      // than 5 bytes, it will corrupt the neighboring thunk. so put a
      // breakpoint and wait until we actually execute this to put the full
      // trampoline.
      BYTE int3 = 0xCC;
      PatchCode(target_address, &int3, 1, targetOriginalBytes);
    } else {
      debug_printf(
          "not executing target address yet... single step over the access\n");
      ExceptionInfo->ContextRecord->EFlags |= 0x100;  // trap flag
      singleStep = 1;
    }

    return EXCEPTION_CONTINUE_EXECUTION;
  }

  if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT) {
    debug_printf("Early breakpoint!!! %p\n",
                 ExceptionInfo->ExceptionRecord->ExceptionAddress);

    LPVOID ip = (LPVOID)ExceptionInfo->ContextRecord->INSTRUCTION_POINTER;
    if (ip == target_address) {
      debug_printf("Reached our target address breakpoint\n");
      // restore the breakpoint
      PatchCode(target_address, targetOriginalBytes, 1, NULL);
      // insert trampoline
      AssembleTrampoline(target_address, (uintptr_t)FuzzingHarness,
                         targetOriginalBytes);
      // resume execution
      return EXCEPTION_CONTINUE_EXECUTION;
    }
    // we ignore other breakpoints
  }

  return EXCEPTION_CONTINUE_SEARCH;
}

LONG WINAPI TemporaryExceptionHandler(EXCEPTION_POINTERS *ExceptionInfo) {
  LPVOID ip = (LPVOID)ExceptionInfo->ContextRecord->INSTRUCTION_POINTER;
  if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT) {
    if (DoesBreakpointExists(ip)) {
      fuzzer_printf("Hit breakpoint %p early\n", ip);
      RestoreBreakpoint(ip);
      return EXCEPTION_CONTINUE_EXECUTION;
    }
  }
  return EXCEPTION_CONTINUE_SEARCH;
}

LONG WINAPI ChildBreakpointHandler(EXCEPTION_POINTERS *ExceptionInfo) {
  // trace_printf("Enter %d\n", handlerReentrancy);
  if (InterlockedIncrement(&handlerReentrancy) != 1) {
    FATAL(
        "The breakpoint handler itself generated an exeption (code=%08x, "
        "IP=%p) !!! Likely the breakpoint handler is faulty!!",
        ExceptionInfo->ExceptionRecord->ExceptionCode,
        ExceptionInfo->ContextRecord->INSTRUCTION_POINTER);
  }

  // single step from ntcreatefile hook
  if (singleStep) {
    if (ExceptionInfo->ExceptionRecord->ExceptionCode !=
        EXCEPTION_SINGLE_STEP) {
      FATAL(
          "Expecting single step trap but instead received exception %08x!!! "
          "Likely the breakpoint handler is faulty!!",
          ExceptionInfo->ExceptionRecord->ExceptionCode);
    }
    // trace_printf("YEET! Got single step at %p\n",
    // ExceptionInfo->ContextRecord->INSTRUCTION_POINTER);

    // patch the NtCreateFile again
    /*if (singleStep == 1)
      hook_NtCreateFile();
    else*/
    if (singleStep == 2) hook_TerminateProcess();

    singleStep = 0;

    // trace_printf("Exit1 %d\n", handlerReentrancy);
    InterlockedDecrement(&handlerReentrancy);
    return EXCEPTION_CONTINUE_EXECUTION;
  }
  if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT) {
    // It's a breakpoint, no big deal, just restore the stolen byte and
    // continue.
    LPVOID ip = (LPVOID)ExceptionInfo->ContextRecord->INSTRUCTION_POINTER;
    if (DoesBreakpointExists(ip)) {
      // trace_printf("hit breakpoint at %p\n", ip);
      if (/*ip == pCreateFile ||*/ ip == pTerminateProcess) {
        // do single step to restore the breakpoint. we'll receive a 'single
        // step' exception (see above).
        ExceptionInfo->ContextRecord->EFlags |= 0x100;  // trap flag
        /*  if (ip == pCreateFile) {
            debug_printf("NtCreateFile hit: %p\n", ip);
            CreateFile_hook(ExceptionInfo);
            singleStep = 1;
          } else*/
        if (ip == pTerminateProcess) {
          debug_printf("TerminateProcess hit: %p\n", ip);
          TerminateProcess_hook(
              ExceptionInfo);  // This may lead to report_end(), so we need to
                               // remember to decrement the re-entry counter if
                               // that is the case.
          singleStep = 2;
        } else
          FATAL("Wrong single step value");

        RestoreBreakpoint(ip);
      } else if (ip == pRtlExitUserProcess) {
        debug_printf("RtlExitUserProcess basicblock: %p\n", ip);
        report_end();
      } else {
        debug_printf("Covered basicblock %p\n", ip);
        BreakpointInfo bp = RestoreBreakpoint(ip);
        child_report_coverage((uintptr_t)ip, bp);

        // weird case
        if (bp.original_byte == 0xCC) {
          fuzzer_printf(
              "We seem to have placed a breakpoint on top of an existing "
              "breakpoint, check bb-file (duplicated breakpoint?)\n");
          // exception will eventually bubble up to ChildCrashHandler.
          // trace_printf("Exit2 %d\n", handlerReentrancy);
          InterlockedDecrement(&handlerReentrancy);
          return EXCEPTION_CONTINUE_SEARCH;
        }
      }
      // trace_printf("Exit3 %d\n", handlerReentrancy);
      InterlockedDecrement(&handlerReentrancy);
      return EXCEPTION_CONTINUE_EXECUTION;
    } else {
      debug_printf("We hit breakpoint but it's not ours?");
    }
  }
  debug_printf("Ignoring exception %08x at %p, referencing %p\n",
               ExceptionInfo->ExceptionRecord->ExceptionCode,
               (void *)ExceptionInfo->ContextRecord->INSTRUCTION_POINTER,
               ExceptionInfo->ExceptionRecord->ExceptionAddress);
  // trace_printf("Exit4 %d\n", handlerReentrancy);
  InterlockedDecrement(&handlerReentrancy);
  return EXCEPTION_CONTINUE_SEARCH;
}

LONG WINAPI ChildCrashHandler(EXCEPTION_POINTERS *ExceptionInfo) {
  fuzzer_printf("Uncaught exception %08x at instruction %p, referencing %p\n",
                ExceptionInfo->ExceptionRecord->ExceptionCode,
                ExceptionInfo->ContextRecord->INSTRUCTION_POINTER,
                ExceptionInfo->ExceptionRecord->ExceptionAddress);
  report_crashed(ExceptionInfo->ExceptionRecord->ExceptionCode,
                 ExceptionInfo->ContextRecord->INSTRUCTION_POINTER,
                 (uint64_t)ExceptionInfo->ExceptionRecord->ExceptionAddress);
  bye();
  return EXCEPTION_EXECUTE_HANDLER;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call,
                      LPVOID lpReserved) {
  switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
      CreateThread(NULL, 0, cbThreadStart, hModule, NULL, NULL);
      break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
      break;
  }
  return TRUE;
}

const char *get_module_filename(HMODULE hModule) {
  static std::unordered_map<HMODULE, std::string> module_filenames;

  if (module_filenames.find(hModule) == module_filenames.end()) {
    char buf[1000];
    if (!GetModuleFileNameA(hModule, buf, sizeof(buf))) {
      FATAL("GetModuleFileNameA");
    }
    char *basename = strrchr(buf, '\\');
    if (basename)
      basename++;
    else
      basename = buf;
    module_filenames.emplace(hModule, basename);
  }
  return module_filenames[hModule].c_str();
}

// This is kinda sketchy because other threads might not be suspended and may
// end up executing the code as we're patching it. Ideally we should suspend all
// the other threads before doing any code patching, but I feel like that would
// just cause even more problems.
void PatchCode(LPVOID target, _In_ const BYTE *bytes, _In_ size_t len,
               _Out_opt_ BYTE *stolenBytes) {
  // trace_printf("Patch %p len %d\n", target, len);

  DWORD dwOldProtect;
  if (!VirtualProtect(target, len, PAGE_EXECUTE_READWRITE, &dwOldProtect)) {
    FATAL("VirtualProtect failed!! (write) :(\n");
  }

  uintptr_t aligned = ((uintptr_t)target) & ~0xfULL;
  uintptr_t end = ((uintptr_t)target) + len;
  uintptr_t aligned_size = end - aligned;

  if (len == 1)  // Special case because we use CC int3 a lot
  {
    // We can do it atomically using lock cmpxchg
    BYTE stolenByte = _InterlockedExchange8((volatile CHAR *)target, *bytes);
    if (stolenBytes) *stolenBytes = stolenByte;
  }
#ifdef _WIN64
  else if (aligned_size < 16) {
    // We can do it atomically using lock cmpxchg16b. All modern CPUs support
    uintptr_t offset = (uintptr_t)target - aligned;
    BYTE orig_bytes[16];
    BYTE new_bytes[16];
    memcpy(orig_bytes, (LPVOID)aligned, 16);
    memcpy(new_bytes, orig_bytes, 16);
    memcpy(new_bytes + offset, bytes, len);
    char success = _InterlockedCompareExchange128(
        (volatile LONG64 *)aligned, *(LONG64 *)&new_bytes[8],
        *(LONG64 *)&new_bytes[0], (LONG64 *)orig_bytes);
    if (!success) {
      FATAL("Atomic PatchCode failed!");
    }
    if (stolenBytes) memcpy(stolenBytes, orig_bytes + offset, len);
  }
#endif
  else {
    // We can't do the write atomically (straddling multiple cache lines) so
    // just resort to plain-old memcpy.
    if (stolenBytes) memcpy(stolenBytes, target, len);
    memcpy(target, bytes, len);
  }

  DWORD trash;
  if (!VirtualProtect(target, len, dwOldProtect, &trash)) {
    FATAL("VirtualProtect failed!! (restore) :(\n");
  }
  FlushInstructionCache(GetCurrentProcess(), target, len);
}

void InstallBreakpoint(HMODULE hModule, uintptr_t rva) {
  const std::lock_guard<std::mutex> lock(breakpoints_mutex);

  const BYTE int3 = 0xcc;
  BYTE stolenByte = NULL;
  PBYTE target = (PBYTE)hModule + rva;
  // trace_printf("install break: %p\n", target);
  if (breakpoints.find(target) != breakpoints.end()) {
    FATAL("InstallBreakpoint: duplicate breakpoint detected, check bb-file");
  }

  PatchCode(target, &int3, 1, &stolenByte);
  breakpoints[target] = {stolenByte, hModule};
}

// uninstall breakpoint
BreakpointInfo RestoreBreakpoint(LPVOID target) {
  const std::lock_guard<std::mutex> lock(breakpoints_mutex);

  if (breakpoints.find(target) == breakpoints.cend()) {
    FATAL("RestoreBreakpoint: attempting to restore nonexistent breakpoint");
  }

  BreakpointInfo breakpoint = breakpoints[target];
  // trace_printf("The stolen byte was %p\n", stolenByte);
  breakpoints.erase(target);
  PatchCode(target, &breakpoint.original_byte, 1, NULL);
  return breakpoint;
}

BOOL DoesBreakpointExists(LPVOID target) {
  const std::lock_guard<std::mutex> lock(breakpoints_mutex);

  return breakpoints.find(target) != breakpoints.cend();
}

void hook_NtCreateFile() {
  static HMODULE hNtdll = GetModuleHandleA("ntdll");
  // InstallBreakpoint(hNtdll, (uintptr_t)pCreateFile - (uintptr_t)hNtdll);
}

void hook_TerminateProcess() {
  static HMODULE hKernel32 = GetModuleHandleA("kernel32");
  InstallBreakpoint(hKernel32,
                    (uintptr_t)pTerminateProcess - (uintptr_t)hKernel32);
}

void hook_RtlExitUserProcess() {
  static HMODULE hNtdll = GetModuleHandleA("ntdll");
  InstallBreakpoint(hNtdll, (uintptr_t)pRtlExitUserProcess - (uintptr_t)hNtdll);
}

[[noreturn]] void bye() { Sleep(INFINITE); }

[[noreturn]] void suicide() {
  // debug_printf("check restore\n");
  if (DoesBreakpointExists(pTerminateProcess)) {
    debug_printf("do restore\n");
    RestoreBreakpoint(pTerminateProcess);
  }
  debug_printf("bye!\n");
  TerminateProcess(GetCurrentProcess(), 0);
}