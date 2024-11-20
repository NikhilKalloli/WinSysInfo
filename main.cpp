#include "SystemAnalyzer.h"

int main() {
    SystemAnalyzer analyzer;
    
    wprintf(L"Windows System Analyzer v1.0\n");
    wprintf(L"============================\n");
    
    analyzer.PrintSystemInfo();
    analyzer.MonitorSystemPerformance();
    analyzer.AnalyzeDrives();
    analyzer.ListProcesses();
    analyzer.GetSecurityInfo();
    
    wprintf(L"\n\nPress any key to exit...");
    getchar();
    return 0;
} 