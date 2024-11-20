#include "SystemAnalyzer.h"
#include <memory>

void SystemAnalyzer::PrintSystemInfo() {
    wchar_t infoBuf[BUFFER_SIZE];
    DWORD bufCharCount = BUFFER_SIZE;

    // System Name
    if (GetComputerName(infoBuf, &bufCharCount)) {
        wprintf(L"\n=== System Information ===");
        wprintf(L"\nComputer Name: %s", infoBuf);
    }

    // OS Information
    OSVERSIONINFO osInfo = { sizeof(OSVERSIONINFO) };
    if (GetVersionEx(&osInfo)) {
        wprintf(L"\nOS Version: %d.%d Build %d",
            osInfo.dwMajorVersion,
            osInfo.dwMinorVersion,
            osInfo.dwBuildNumber);
    }

    // Processor Information
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    wprintf(L"\nNumber of Processors: %d", sysInfo.dwNumberOfProcessors);
    wprintf(L"\nProcessor Architecture: ");
    
    switch (sysInfo.wProcessorArchitecture) {
        case PROCESSOR_ARCHITECTURE_AMD64:
            wprintf(L"x64 (AMD or Intel)");
            break;
        case PROCESSOR_ARCHITECTURE_ARM:
            wprintf(L"ARM");
            break;
        case PROCESSOR_ARCHITECTURE_INTEL:
            wprintf(L"x86");
            break;
        default:
            wprintf(L"Unknown");
    }
}

void SystemAnalyzer::MonitorSystemPerformance() {
    MEMORYSTATUSEX memInfo = { sizeof(MEMORYSTATUSEX) };
    
    if (GlobalMemoryStatusEx(&memInfo)) {
        wprintf(L"\n\n=== Memory Information ===");
        wprintf(L"\nTotal Physical Memory: %.2f GB", 
            (double)memInfo.ullTotalPhys / (1024 * 1024 * 1024));
        wprintf(L"\nAvailable Physical Memory: %.2f GB", 
            (double)memInfo.ullAvailPhys / (1024 * 1024 * 1024));
        wprintf(L"\nMemory Load: %ld%%", memInfo.dwMemoryLoad);
    }
}

void SystemAnalyzer::AnalyzeDrives() {
    wprintf(L"\n\n=== Drive Information ===");
    wchar_t drives[MAX_PATH];
    
    if (GetLogicalDriveStrings(MAX_PATH, drives)) {
        wchar_t* drive = drives;
        while (*drive) {
            UINT driveType = GetDriveType(drive);
            wprintf(L"\nDrive %s - ", drive);
            
            switch (driveType) {
                case DRIVE_FIXED:
                    wprintf(L"Fixed Drive");
                    ULARGE_INTEGER freeSpace, totalSpace;
                    if (GetDiskFreeSpaceEx(drive, &freeSpace, &totalSpace, NULL)) {
                        wprintf(L"\n  Total Space: %.2f GB", 
                            (double)totalSpace.QuadPart / (1024 * 1024 * 1024));
                        wprintf(L"\n  Free Space: %.2f GB", 
                            (double)freeSpace.QuadPart / (1024 * 1024 * 1024));
                    }
                    break;
                case DRIVE_REMOVABLE:
                    wprintf(L"Removable Drive");
                    break;
                case DRIVE_CDROM:
                    wprintf(L"CD/DVD Drive");
                    break;
                case DRIVE_REMOTE:
                    wprintf(L"Network Drive");
                    break;
            }
            drive += wcslen(drive) + 1;
        }
    }
}

void SystemAnalyzer::ListProcesses() {
    wprintf(L"\n\n=== Running Processes ===");
    
    // Get process list
    DWORD processes[1024], cbNeeded;
    if (!EnumProcesses(processes, sizeof(processes), &cbNeeded)) {
        PrintError(L"Failed to enumerate processes");
        return;
    }

    // Calculate number of processes
    DWORD numProcesses = cbNeeded / sizeof(DWORD);

    // Iterate through each process
    for (DWORD i = 0; i < numProcesses; i++) {
        if (processes[i] != 0) {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                                       FALSE, processes[i]);
            
            if (hProcess != NULL) {
                wchar_t processName[MAX_PATH] = L"<unknown>";
                
                HMODULE hMod;
                DWORD cbNeededMod;
                
                if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeededMod)) {
                    GetModuleBaseName(hProcess, hMod, processName, 
                                    sizeof(processName)/sizeof(wchar_t));
                }

                // Get process memory info
                PROCESS_MEMORY_COUNTERS pmc;
                if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
                    wprintf(L"\nProcess: %s (PID: %lu)", processName, processes[i]);
                    wprintf(L"\n  Working Set Size: %.2f MB", 
                           (double)pmc.WorkingSetSize / (1024 * 1024));
                }
                
                CloseHandle(hProcess);
            }
        }
    }
}

void SystemAnalyzer::GetSecurityInfo() {
    wprintf(L"\n\n=== Security Information ===");
    
    // Get current user name
    wchar_t userName[BUFFER_SIZE];
    DWORD userNameSize = BUFFER_SIZE;
    if (GetUserName(userName, &userNameSize)) {
        wprintf(L"\nCurrent User: %s", userName);
    }

    // Check if running as administrator
    BOOL isElevated = FALSE;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD cbSize = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(hToken, TokenElevation, &elevation,
                              sizeof(elevation), &cbSize)) {
            isElevated = elevation.TokenIsElevated;
        }
        CloseHandle(hToken);
    }
    
    wprintf(L"\nAdmin Privileges: %s", isElevated ? L"Yes" : L"No");

    // Get Windows Defender status
    HKEY hKey;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                     L"SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection",
                     0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD value;
        DWORD dataSize = sizeof(DWORD);
        if (RegQueryValueEx(hKey, L"DisableRealtimeMonitoring", NULL, NULL,
                           (LPBYTE)&value, &dataSize) == ERROR_SUCCESS) {
            wprintf(L"\nReal-time Protection: %s", 
                   value == 0 ? L"Enabled" : L"Disabled");
        }
        RegCloseKey(hKey);
    }
}

void SystemAnalyzer::PrintError(const wchar_t* msg) {
    DWORD error = GetLastError();
    wchar_t errorMsg[BUFFER_SIZE];
    
    FormatMessage(
        FORMAT_MESSAGE_FROM_SYSTEM,
        NULL,
        error,
        0,
        errorMsg,
        BUFFER_SIZE,
        NULL
    );
    
    wprintf(L"Error: %s - %s\n", msg, errorMsg);
} 