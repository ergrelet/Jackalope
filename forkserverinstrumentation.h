#pragma once

#include <windows.h>
#include <winternl.h>  // CLIENT_ID

#include <cinttypes>
#include <filesystem>
#include <string>

#include "coverage.h"
#include "instrumentation.h"
#include "runresult.h"

class WinnieForkServerInstrumentation final : public Instrumentation {
 public:
  ~WinnieForkServerInstrumentation();

  void Init(int argc, char **argv) override;

  RunResult Run(int argc, char **argv, uint32_t init_timeout,
                uint32_t timeout) override;
  RunResult RunWithCrashAnalysis(int argc, char **argv, uint32_t init_timeout,
                                 uint32_t timeout) override;

  void CleanTarget() override;

  bool HasNewCoverage() override;
  void GetCoverage(Coverage &coverage, bool clear_coverage) override;
  void ClearCoverage() override;
  void IgnoreCoverage(Coverage &coverage) override;

  uint64_t GetReturnValue() override;

  std::string GetCrashName() override;

 private:
  DWORD SpawnForkServer(char *cmd, uint32_t timeout, uint32_t init_timeout);
  CLIENT_ID SpawnTargetAndInjectAgent(char *cmd, uint32_t timeout,
                                      uint32_t init_timeout);

 protected:
  std::string target_module;
  std::string target_method;
  size_t target_offset;
  std::filesystem::path bb_file_path;
  bool persist;
  int num_iterations;
  int cur_iteration;
  bool fork_server_started;
};
