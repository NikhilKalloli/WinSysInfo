#pragma once
#include <windows.h>
#include <stdio.h>
#include <psapi.h>
#include <securitybaseapi.h>

class SystemAnalyzer {
public:
    void PrintSystemInfo();
    void MonitorSystemPerformance();
    void AnalyzeDrives();
    void ListProcesses();
    void GetSecurityInfo();

private:
    void PrintError(const wchar_t* msg);
    static const int BUFFER_SIZE = 32767;
}; 