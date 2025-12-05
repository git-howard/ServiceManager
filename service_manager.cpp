#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#include <winsock2.h>
#include <iphlpapi.h>
#include <windows.h>
#include <winsvc.h>
#include <tlhelp32.h>
#include <commctrl.h>
#include <dwmapi.h>
#include <uxtheme.h>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <ctime>
#include <algorithm>
#include <direct.h>
#include <map>
#include <thread>
#include <chrono>
#include <mutex>
#include <deque>

// Link with comctl32.lib
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "uxtheme.lib")
#pragma comment(lib, "Msimg32.lib")

#ifndef DWMWA_USE_IMMERSIVE_DARK_MODE
#define DWMWA_USE_IMMERSIVE_DARK_MODE 20
#endif
#ifndef DWMWA_WINDOW_CORNER_PREFERENCE
#define DWMWA_WINDOW_CORNER_PREFERENCE 33
#endif
#ifndef DWMWCP_DEFAULT
#define DWMWCP_DEFAULT 0
#define DWMWCP_DONOTROUND 1
#define DWMWCP_ROUND 2
#define DWMWCP_ROUNDSMALL 3
#endif

// Control IDs
#define ID_LISTVIEW 1001
#define ID_BTN_ADD 1002
#define ID_BTN_EDIT 1003
#define ID_BTN_DEL 1004
#define ID_BTN_START 1005
#define ID_BTN_STOP 1006
#define ID_BTN_STARTALL 1007
#define ID_BTN_STOPALL 1008
#define ID_BTN_TRAY 1009
#define ID_TIMER_UPDATE 1010
#define ID_MENU_START 1011
#define ID_MENU_STOP 1012
#define ID_MENU_EDIT 1013
#define ID_MENU_DEL 1014
#define ID_MENU_LOG 1015
#define ID_MENU_RESTART 1023
#define ID_MENU_MOVE_UP 1024
#define ID_MENU_MOVE_DOWN 1025
#define ID_TRAY_ICON 1016
#define WM_TRAYICON (WM_USER + 1)
#define ID_TRAY_EXIT 1017
#define ID_TRAY_RESTORE 1018
#define ID_BTN_INSTALL_SVC 1019
#define ID_BTN_UNINSTALL_SVC 1020
#define ID_LINK_AUTHOR 1021
#define ID_BTN_ABOUT 1022
#define IDM_ABOUT 2000
#define ID_LINK_ABOUT 2001
#define ID_BTN_SYSTEM_SERVICE 2022
#define ID_MENU_SYS_INSTALL_START 2023
#define ID_MENU_SYS_STOP_DELETE 2024
#define ID_MENU_SYS_START 2025
#define ID_MENU_SYS_STOP 2026
#define ID_MENU_SYS_RESTART 2027
#define WM_REQ_START_FROM_QUEUE (WM_USER + 2)

// Dialog Control IDs

// Dialog Control IDs
#define ID_EDIT_NAME 2001
#define ID_EDIT_SCRIPT 2002
#define ID_COMBO_TYPE 2003
#define ID_EDIT_PYTHON 2004
#define ID_EDIT_ARGS 2005
#define ID_EDIT_WORKDIR 2006
#define ID_BTN_OK 2007
#define ID_BTN_CANCEL 2008
#define ID_BTN_BROWSE_SCRIPT 2009
#define ID_BTN_BROWSE_PYTHON 2010
#define ID_BTN_BROWSE_WORKDIR 2011
#define ID_CHECK_AUTOSTART 2012
#define ID_CHECK_HIDECONSOLE 2013
#define ID_CHECK_AUTORESTART 2015
#define ID_LABEL_PYTHON 2014
#define ID_TAB_CONTROL 2016
#define ID_LABEL_NAME 2017
#define ID_LABEL_TYPE 2018
#define ID_LABEL_SCRIPT 2019
#define ID_LABEL_ARGS 2020
#define ID_LABEL_WORKDIR 2021
#define ID_EDIT_LOG 2028

// Global Variables
HINSTANCE hInst;
HWND hMainWnd;
HWND hListView;
HWND hLogEdit = NULL;
HFONT hFont;
NOTIFYICONDATA nid;
bool isMinimizedToTray = false;

// Global queue for sequential startup
std::deque<std::string> g_pendingStarts;
std::mutex g_pendingMutex;

// Utility Functions for Encoding
std::wstring Utf8ToWide(const std::string& str) {
    if (str.empty()) return L"";
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}

std::string WideToUtf8(const std::wstring& wstr) {
    if (wstr.empty()) return "";
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

// Enable modern look: dark titlebar and rounded corners
void EnableModernWindow(HWND hwnd) {
    BOOL dark = TRUE;
    DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, &dark, sizeof(dark));
    int corner = DWMWCP_ROUND;
    DwmSetWindowAttribute(hwnd, DWMWA_WINDOW_CORNER_PREFERENCE, &corner, sizeof(corner));
}

// Service Structure
struct Service {
    std::string name;
    std::string script_path;
    std::string service_type;
    std::string python_path;
    std::string args;
    std::string work_dir;
    
    DWORD pid = 0;
    HANDLE hProcess = NULL;
    std::string status = "已停止";
    time_t start_time = 0;
    bool auto_start = false;
    bool hide_console = true;
    bool auto_restart = false;
    std::string ports;
    
    // Runtime tracking
    bool expected_stop = true;
    time_t crash_time = 0;
    std::deque<time_t> restart_timestamps;

    std::string get_runtime() {
        if (status != "运行中" || start_time == 0) {
            return "00:00:00";
        }
        time_t now = time(0);
        double seconds = difftime(now, start_time);
        int h = (int)(seconds / 3600);
        int m = (int)((seconds - h * 3600) / 60);
        int s = (int)(seconds - h * 3600 - m * 60);
        
        char buffer[64];
        snprintf(buffer, sizeof(buffer), "%02d:%02d:%02d", h, m, s);
        return std::string(buffer);
    }
};

void AppendLog(const std::string& msg) {
    if (!hLogEdit) return;
    
    time_t now = time(0);
    struct tm tstruct;
    char buf[80];
    tstruct = *localtime(&now);
    strftime(buf, sizeof(buf), "[%Y-%m-%d %H:%M:%S] ", &tstruct);
    
    std::string fullMsg = std::string(buf) + msg + "\r\n";
    std::wstring wMsg = Utf8ToWide(fullMsg);
    
    int len = GetWindowTextLengthW(hLogEdit);
    SendMessageW(hLogEdit, EM_SETSEL, len, len);
    SendMessageW(hLogEdit, EM_REPLACESEL, FALSE, (LPARAM)wMsg.c_str());
}

// Helper to get executable directory
std::string GetBasePath() {
    wchar_t buffer[MAX_PATH];
    GetModuleFileNameW(NULL, buffer, MAX_PATH);
    std::wstring fullPath = buffer;
    size_t pos = fullPath.find_last_of(L"\\/");
    if (pos != std::wstring::npos) {
        std::wstring dirPath = fullPath.substr(0, pos);
        return WideToUtf8(dirPath);
    }
    return ".";
}

// PID File Helpers
void write_pid_file(const std::string& name, DWORD pid, time_t start_time) {
    std::string base = GetBasePath();
    std::string dir = base + "\\pids";
    std::wstring wDir = Utf8ToWide(dir);
    
    // 创建目录，忽略已存在的错误
    int mkdir_result = _wmkdir(wDir.c_str());
    if (mkdir_result != 0 && errno != EEXIST) {
        // 目录创建失败且不是因为已存在
        std::wstring msg = L"无法创建PID目录\n目录路径: " + wDir + 
                          L"\n_wmkdir返回: " + std::to_wstring(mkdir_result) +
                          L"\nerrno: " + std::to_wstring(errno) +
                          L"\n基础路径: " + Utf8ToWide(base);
        OutputDebugStringW(msg.c_str());
        MessageBoxW(NULL, msg.c_str(), L"目录创建失败", MB_OK | MB_ICONERROR);
    }
    
    std::string pidFile = dir + "\\" + name + ".pid";
    std::wstring wPidFile = Utf8ToWide(pidFile);
    
    // 使用Windows API写入文件
    HANDLE hFile = CreateFileW(wPidFile.c_str(), GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        std::string content = std::to_string(pid) + " " + std::to_string(start_time);
        DWORD written;
        WriteFile(hFile, content.c_str(), (DWORD)content.length(), &written, NULL);
        CloseHandle(hFile);
    } else {
        // 文件创建失败
        DWORD err = GetLastError();
        std::wstring msg = L"无法创建PID文件\n文件路径: " + wPidFile + 
                          L"\n错误码: " + std::to_wstring(err) +
                          L"\n目录路径: " + wDir;
        OutputDebugStringW(msg.c_str());
        MessageBoxW(NULL, msg.c_str(), L"PID文件创建失败", MB_OK | MB_ICONERROR);
    }
}

bool read_pid_file(const std::string& name, DWORD& pid, time_t& start_time) {
    std::string base = GetBasePath();
    std::string pidFile = base + "\\pids\\" + name + ".pid";
    std::wstring wPidFile = Utf8ToWide(pidFile);
    
    // 使用Windows API读取文件
    HANDLE hFile = CreateFileW(wPidFile.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        char buffer[128];
        DWORD bytesRead;
        if (ReadFile(hFile, buffer, sizeof(buffer) - 1, &bytesRead, NULL)) {
            buffer[bytesRead] = '\0';
            CloseHandle(hFile);
            if (sscanf(buffer, "%lu %lld", &pid, &start_time) == 2) {
                return true;
            }
        } else {
            CloseHandle(hFile);
        }
    }
    return false;
}

void remove_pid_file(const std::string& name) {
    std::string base = GetBasePath();
    std::string path = base + "\\pids\\" + name + ".pid";
    std::wstring wPath = Utf8ToWide(path);
    DeleteFileW(wPath.c_str());
}

bool IsSystemServiceRunning() {
    SC_HANDLE hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCM) return false;
    SC_HANDLE hSvc = OpenServiceW(hSCM, L"ServiceManager", SERVICE_QUERY_STATUS);
    if (!hSvc) { CloseServiceHandle(hSCM); return false; }
    SERVICE_STATUS_PROCESS ssStatus;
    DWORD dwBytesNeeded;
    bool running = false;
    if (QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssStatus, sizeof(SERVICE_STATUS_PROCESS), &dwBytesNeeded)) {
        running = (ssStatus.dwCurrentState != SERVICE_STOPPED);
    }
    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);
    return running;
}

void NotifyServiceConfigChange() {
    SC_HANDLE hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCM) return;
    SC_HANDLE hSvc = OpenServiceW(hSCM, L"ServiceManager", SERVICE_USER_DEFINED_CONTROL);
    if (hSvc) {
        SERVICE_STATUS status;
        ControlService(hSvc, 128, &status);
        CloseServiceHandle(hSvc);
    }
    CloseServiceHandle(hSCM);
}

// Helper to get ports
// Helper to get ports for a process tree
std::string GetServicePorts(DWORD rootPid) {
    if (rootPid == 0) return "";
    
    // Get all descendant PIDs
    std::vector<DWORD> pids;
    pids.push_back(rootPid);
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        std::vector<PROCESSENTRY32> allProcs;
        
        if (Process32First(hSnapshot, &pe32)) {
            do {
                allProcs.push_back(pe32);
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);

        // Build map
        std::map<DWORD, std::vector<DWORD>> parentToChildren;
        for (const auto& p : allProcs) {
            parentToChildren[p.th32ParentProcessID].push_back(p.th32ProcessID);
        }

        // BFS
        size_t i = 0;
        while (i < pids.size()) {
            DWORD curr = pids[i++];
            if (parentToChildren.count(curr)) {
                for (DWORD child : parentToChildren[curr]) {
                    pids.push_back(child);
                }
            }
        }
    }
    
    std::sort(pids.begin(), pids.end());

    std::string ports;
    std::vector<int> portList;

    // TCP
    PMIB_TCPTABLE_OWNER_PID pTcpTable;
    DWORD dwSize = 0;
    if (GetExtendedTcpTable(NULL, &dwSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == ERROR_INSUFFICIENT_BUFFER) {
        pTcpTable = (PMIB_TCPTABLE_OWNER_PID)malloc(dwSize);
        if (GetExtendedTcpTable(pTcpTable, &dwSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
            for (DWORD i = 0; i < pTcpTable->dwNumEntries; i++) {
                if (std::binary_search(pids.begin(), pids.end(), pTcpTable->table[i].dwOwningPid)) {
                    if (pTcpTable->table[i].dwState == MIB_TCP_STATE_LISTEN) {
                        int port = ntohs((u_short)pTcpTable->table[i].dwLocalPort);
                        if (std::find(portList.begin(), portList.end(), port) == portList.end()) {
                            portList.push_back(port);
                        }
                    }
                }
            }
        }
        free(pTcpTable);
    }

    // UDP
    PMIB_UDPTABLE_OWNER_PID pUdpTable;
    dwSize = 0;
    if (GetExtendedUdpTable(NULL, &dwSize, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == ERROR_INSUFFICIENT_BUFFER) {
        pUdpTable = (PMIB_UDPTABLE_OWNER_PID)malloc(dwSize);
        if (GetExtendedUdpTable(pUdpTable, &dwSize, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
            for (DWORD i = 0; i < pUdpTable->dwNumEntries; i++) {
                if (std::binary_search(pids.begin(), pids.end(), pUdpTable->table[i].dwOwningPid)) {
                    int port = ntohs((u_short)pUdpTable->table[i].dwLocalPort);
                    if (std::find(portList.begin(), portList.end(), port) == portList.end()) {
                        portList.push_back(port);
                    }
                }
            }
        }
        free(pUdpTable);
    }

    std::sort(portList.begin(), portList.end());
    for (size_t i = 0; i < portList.size(); ++i) {
        if (i > 0) ports += ", ";
        ports += std::to_string(portList[i]);
    }
    return ports;
}

// Service Manager Class
class ServiceManager {
public:
    std::vector<Service> services;
    std::string config_file;
    std::string global_python_path;
    int startup_interval;

    ServiceManager(const std::string& cfg_file = "services_config.ini") {
        std::string base = GetBasePath();
        // If cfg_file is relative, prepend base path
        if (cfg_file.find(":") == std::string::npos) {
            config_file = base + "\\" + cfg_file;
        } else {
            config_file = cfg_file;
        }
        global_python_path = "python";
        startup_interval = 1000; // Default 1000 milliseconds
    }

    std::string resolve_path(const std::string& path) {
        if (path.empty()) return "";
        // Check if absolute (Drive letter or UNC)
        if (path.length() >= 2 && path[1] == ':') return path;
        if (path.length() >= 2 && path[0] == '\\' && path[1] == '\\') return path;
        
        // Combine with base path
        std::string combined = GetBasePath() + "\\" + path;
        
        // Use GetFullPathNameA to resolve .. and . properly
        char resolved[MAX_PATH];
        DWORD result = GetFullPathNameA(combined.c_str(), MAX_PATH, resolved, NULL);
        if (result > 0 && result < MAX_PATH) {
            return std::string(resolved);
        }
        
        return combined;
    }

    std::string MakeRelativePath(const std::string& absolutePath) {
        if (absolutePath.empty()) return "";
        
        std::string basePath = GetBasePath();
        std::string absPath = absolutePath;
        
        // Normalize separators to backslash
        for (char& c : absPath) if (c == '/') c = '\\';
        for (char& c : basePath) if (c == '/') c = '\\';
        
        // Convert to lowercase for comparison (Windows is case-insensitive)
        std::string absLower = absPath;
        std::string baseLower = basePath;
        std::transform(absLower.begin(), absLower.end(), absLower.begin(), ::tolower);
        std::transform(baseLower.begin(), baseLower.end(), baseLower.begin(), ::tolower);
        
        // Check if paths are on the same drive
        if (absLower.length() < 2 || baseLower.length() < 2 || absLower[0] != baseLower[0]) {
            return absolutePath; // Different drives, return absolute
        }
        
        // Check if absPath starts with basePath
        if (absLower.find(baseLower) == 0) {
            // Path is under base directory
            size_t baseLen = basePath.length();
            if (absPath.length() > baseLen && absPath[baseLen] == '\\') {
                return absPath.substr(baseLen + 1); // Remove base + separator
            }
        }
        
        // Try to build relative path with ..
        std::vector<std::string> baseParts;
        std::vector<std::string> absParts;
        
        // Split paths
        auto splitPath = [](const std::string& path) -> std::vector<std::string> {
            std::vector<std::string> parts;
            std::string current;
            for (char c : path) {
                if (c == '\\') {
                    if (!current.empty()) {
                        parts.push_back(current);
                        current.clear();
                    }
                } else {
                    current += c;
                }
            }
            if (!current.empty()) parts.push_back(current);
            return parts;
        };
        
        baseParts = splitPath(basePath);
        absParts = splitPath(absPath);
        
        // Find common prefix
        size_t commonLen = 0;
        while (commonLen < baseParts.size() && commonLen < absParts.size()) {
            std::string bp = baseParts[commonLen];
            std::string ap = absParts[commonLen];
            std::transform(bp.begin(), bp.end(), bp.begin(), ::tolower);
            std::transform(ap.begin(), ap.end(), ap.begin(), ::tolower);
            if (bp != ap) break;
            commonLen++;
        }
        
        // Build relative path
        std::string result;
        // Add .. for each remaining part in base
        for (size_t i = commonLen; i < baseParts.size(); i++) {
            if (!result.empty()) result += "\\";
            result += "..";
        }
        // Add remaining parts from abs
        for (size_t i = commonLen; i < absParts.size(); i++) {
            if (!result.empty()) result += "\\";
            result += absParts[i];
        }
        
        return result.empty() ? "." : result;
    }

    std::string trim(const std::string& str) {
        size_t first = str.find_first_not_of(" \t\r\n");
        if (std::string::npos == first) return str;
        size_t last = str.find_last_not_of(" \t\r\n");
        return str.substr(first, (last - first + 1));
    }

    void load_config() {
        std::wstring wConfigFile = Utf8ToWide(config_file);
        std::ifstream file(wConfigFile.c_str());
        if (!file.is_open()) return;

        std::string line;
        std::string current_section;
        Service current_service;
        bool in_service_section = false;
        bool found_startup_interval = false;

        services.clear();

        while (std::getline(file, line)) {
            line = trim(line);
            if (line.empty() || line[0] == ';' || line[0] == '#') continue;

            if (line[0] == '[' && line.back() == ']') {
                if (in_service_section && !current_service.name.empty()) {
                    services.push_back(current_service);
                }

                current_section = line.substr(1, line.size() - 2);
                
                if (current_section == "global") {
                    in_service_section = false;
                } else if (current_section.find("service_") == 0) {
                    in_service_section = true;
                    current_service = Service();
                    current_service.service_type = "python";
                }
            } else {
                size_t eq_pos = line.find('=');
                if (eq_pos != std::string::npos) {
                    std::string key = trim(line.substr(0, eq_pos));
                    std::string value = trim(line.substr(eq_pos + 1));

                    if (current_section == "global") {
                        if (key == "global_python_path") global_python_path = value;
                        else if (key == "startup_interval") {
                            found_startup_interval = true;
                            try {
                                startup_interval = std::stoi(value);
                                if (startup_interval < 0) startup_interval = 0;
                            } catch (...) {
                                startup_interval = 1000;
                            }
                        }
                    } else if (in_service_section) {
                        if (key == "name") current_service.name = value;
                        else if (key == "script_path") current_service.script_path = value;
                        else if (key == "service_type") current_service.service_type = value;
                        else if (key == "python_path") current_service.python_path = value;
                        else if (key == "args") current_service.args = value;
                        else if (key == "work_dir") current_service.work_dir = value;
                        else if (key == "auto_start") current_service.auto_start = (value == "true" || value == "1");
                        else if (key == "hide_console") current_service.hide_console = (value == "true" || value == "1");
                        else if (key == "auto_restart") current_service.auto_restart = (value == "true" || value == "1");
                    }
                }
            }
        }
        if (in_service_section && !current_service.name.empty()) {
            services.push_back(current_service);
        }
        
        if (!found_startup_interval) {
            save_config();
        }
    }

    void save_config() {
        std::wstring wConfigFile = Utf8ToWide(config_file);
        std::ofstream file(wConfigFile.c_str());
        if (!file.is_open()) return;

        file << "[global]\n";
        file << "global_python_path = " << global_python_path << "\n";
        file << "startup_interval = " << startup_interval << "\n\n";

        for (size_t i = 0; i < services.size(); ++i) {
            file << "[service_" << (i + 1) << "]\n";
            file << "name = " << services[i].name << "\n";
            file << "script_path = " << services[i].script_path << "\n";
            file << "service_type = " << services[i].service_type << "\n";
            file << "python_path = " << (services[i].python_path.empty() ? "" : services[i].python_path) << "\n";
            file << "args = " << services[i].args << "\n";
            file << "work_dir = " << services[i].work_dir << "\n";
            file << "auto_start = " << (services[i].auto_start ? "true" : "false") << "\n";
            file << "hide_console = " << (services[i].hide_console ? "true" : "false") << "\n";
            file << "auto_restart = " << (services[i].auto_restart ? "true" : "false") << "\n\n";
        }
        file.close();
        NotifyServiceConfigChange();
    }

    int get_service_index(const std::string& name) {
        for (size_t i = 0; i < services.size(); ++i) {
            if (services[i].name == name) return (int)i;
        }
        return -1;
    }

    void start_service(int index) {
        if (index < 0 || index >= services.size()) return;
        Service& svc = services[index];

        // Reset runtime tracking
        svc.expected_stop = false;
        svc.crash_time = 0;

        if (svc.status == "运行中") return;

        std::string cmd;
        std::string final_python = resolve_path(svc.python_path.empty() ? global_python_path : svc.python_path);
        std::string final_script = resolve_path(svc.script_path);
        std::string final_workdir = svc.work_dir.empty() ? GetBasePath() : resolve_path(svc.work_dir);

        if (svc.service_type == "python") {
            cmd = "\"" + final_python + "\" \"" + final_script + "\" " + svc.args;
        } else if (svc.service_type == "batch") {
            cmd = "cmd /c \"" + final_script + "\" " + svc.args;
        } else if (svc.service_type == "executable") {
            cmd = "\"" + final_script + "\" " + svc.args;
        } else {
            cmd = "\"" + final_python + "\" \"" + final_script + "\" " + svc.args;
        }

        STARTUPINFOW si;
        PROCESS_INFORMATION pi;
        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        ZeroMemory(&pi, sizeof(pi));

        std::wstring wWorkDir = Utf8ToWide(final_workdir);
        std::wstring wCmd = Utf8ToWide(cmd);

        std::string base = GetBasePath();
        std::string log_dir = base + "\\logs";
        std::wstring wLogDir = Utf8ToWide(log_dir);
        
        // 创建目录，忽略已存在的错误
        if (_wmkdir(wLogDir.c_str()) != 0 && errno != EEXIST) {
            std::wstring msg = L"无法创建日志目录: " + wLogDir + L"\n错误码: " + std::to_wstring(errno);
            OutputDebugStringW(msg.c_str());
        }
        
        std::string log_file = log_dir + "\\" + svc.name + ".log";
        
        SECURITY_ATTRIBUTES sa;
        sa.nLength = sizeof(sa);
        sa.lpSecurityDescriptor = NULL;
        sa.bInheritHandle = TRUE;

        // 使用宽字符版本避免中文文件名乱码
        std::wstring wLogFile = Utf8ToWide(log_file);
        HANDLE hLogFile = CreateFileW(wLogFile.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        
        if (hLogFile != INVALID_HANDLE_VALUE) {
            // 将文件指针移到末尾以实现追加写入
            SetFilePointer(hLogFile, 0, NULL, FILE_END);
        } else {
            // 日志文件创建失败
            std::wstring msg = L"无法创建日志文件: " + wLogFile + L"\n错误码: " + std::to_wstring(GetLastError());
            OutputDebugStringW(msg.c_str());
        }
        
        if (hLogFile != INVALID_HANDLE_VALUE) {
            si.dwFlags |= STARTF_USESTDHANDLES;
            si.hStdOutput = hLogFile;
            si.hStdError = hLogFile;
        }

        // Use CREATE_NO_WINDOW to hide console if hide_console is enabled
        DWORD flags = svc.hide_console ? CREATE_NO_WINDOW : 0; 

        if (CreateProcessW(NULL, &wCmd[0], NULL, NULL, TRUE, flags, NULL, wWorkDir.c_str(), &si, &pi)) {
            svc.pid = pi.dwProcessId;
            svc.hProcess = pi.hProcess;
            svc.status = "运行中";
            svc.start_time = time(0);
            write_pid_file(svc.name, svc.pid, svc.start_time);
            AppendLog(svc.name + " 启动成功 (PID: " + std::to_string(svc.pid) + ")");
            
            CloseHandle(pi.hThread);
            if (hLogFile != INVALID_HANDLE_VALUE) CloseHandle(hLogFile);
        } else {
            if (hLogFile != INVALID_HANDLE_VALUE) CloseHandle(hLogFile);
            AppendLog(svc.name + " 启动失败");
            // Only show message box if we are in GUI mode (roughly check if window exists or not service)
            // But this class is shared. For now, simple check:
            if (GetConsoleWindow() || FindWindowW(L"ServiceManagerClass", NULL))
                MessageBoxW(NULL, L"启动服务失败", L"错误", MB_OK | MB_ICONERROR);
        }
    }

    void stop_service(int index) {
        if (index < 0 || index >= services.size()) return;
        Service& svc = services[index];

        svc.expected_stop = true;
        AppendLog("正在停止服务: " + svc.name);

        if (svc.status != "运行中") return;

        std::string cmd = "taskkill /F /T /PID " + std::to_string(svc.pid);
        std::wstring wCmd = Utf8ToWide(cmd);
        
        STARTUPINFOW si = {0};
        si.cb = sizeof(si);
        PROCESS_INFORMATION pi = {0};
        
        if (CreateProcessW(NULL, &wCmd[0], NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            WaitForSingleObject(pi.hProcess, 1000);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }

        // Fallback: Force terminate if handle exists or can be opened
        if (svc.hProcess) {
            TerminateProcess(svc.hProcess, 0);
            CloseHandle(svc.hProcess);
            svc.hProcess = NULL;
        } else if (svc.pid != 0) {
            HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, svc.pid);
            if (hProc) {
                TerminateProcess(hProc, 0);
                CloseHandle(hProc);
            }
        }
        
        svc.pid = 0;
        svc.status = "已停止";
        remove_pid_file(svc.name);
        AppendLog(svc.name + " 已停止");
    }

    void check_status() {
        time_t now = time(0);
        for (size_t i = 0; i < services.size(); ++i) {
            Service& svc = services[i];
            // Try to recover state from PID file if memory state is empty
            if (svc.pid == 0) {
                DWORD fPid;
                time_t fTime;
                if (read_pid_file(svc.name, fPid, fTime)) {
                    svc.pid = fPid;
                    svc.start_time = fTime;
                    svc.status = "运行中"; // Assume running until checked
                    svc.expected_stop = false; // Recovered, so it should be running
                }
            }

            if (svc.pid != 0) {
                if (!svc.hProcess) {
                    svc.hProcess = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_INFORMATION, FALSE, svc.pid);
                }

                bool is_running = false;
                if (svc.hProcess) {
                    DWORD exitCode;
                    if (GetExitCodeProcess(svc.hProcess, &exitCode)) {
                        if (exitCode == STILL_ACTIVE) {
                            is_running = true;
                            svc.status = "运行中";
                        }
                    }
                } else {
                    // OpenProcess failed. 
                    if (GetLastError() == ERROR_ACCESS_DENIED) {
                        is_running = true;
                        svc.status = "运行中";
                    }
                }

                if (!is_running) {
                    svc.status = "已停止";
                    svc.pid = 0;
                    svc.ports = "";
                    if (svc.hProcess) {
                        CloseHandle(svc.hProcess);
                        svc.hProcess = NULL;
                    }
                    remove_pid_file(svc.name);

                    // Abnormal exit handling: Record crash time
                    if (!svc.expected_stop) {
                        AppendLog(svc.name + " 异常退出");
                        if (svc.crash_time == 0) {
                            svc.crash_time = now;
                        }
                    }
                } else {
                    svc.ports = GetServicePorts(svc.pid);
                    // It is running, reset crash time if any
                    svc.crash_time = 0;
                }
            } 
            
            // Check for restart (if stopped and not expected)
            // This runs if pid was 0 initially OR if it became 0 above
            if (svc.pid == 0) {
                svc.status = "已停止";
                svc.ports = "";
                
                if (!svc.expected_stop && svc.auto_restart && svc.crash_time != 0) {
                    // Prune old restart timestamps (> 60 seconds)
                    while (!svc.restart_timestamps.empty() && (now - svc.restart_timestamps.front() > 60)) {
                        svc.restart_timestamps.pop_front();
                    }

                    if (svc.restart_timestamps.size() < 3) {
                        if (difftime(now, svc.crash_time) >= 1.0) {
                            svc.restart_timestamps.push_back(now);
                            AppendLog(svc.name + " 尝试自动重启...");
                            start_service((int)i);
                        }
                    }
                }
            }
        }
    }
};

ServiceManager g_manager;

// Worker thread for sequential startup
void StartupThreadFunc(HWND hwnd, std::vector<std::string> names, int interval) {
    for (const auto& name : names) {
        // Add to queue
        {
            std::lock_guard<std::mutex> lock(g_pendingMutex);
            g_pendingStarts.push_back(name);
        }
        
        // Notify UI
        PostMessage(hwnd, WM_REQ_START_FROM_QUEUE, 0, 0);
        
        // Sleep
        if (interval > 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(interval));
        }
    }
}

// Dialog Logic
struct DialogData {
    bool is_edit;
    int service_index;
    Service result_service;
};

DialogData g_dialogData;

LRESULT CALLBACK DialogProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE: {
            // Create Tab Control
            HWND hTab = CreateWindowW(WC_TABCONTROL, L"", WS_CHILD | WS_CLIPSIBLINGS | WS_VISIBLE, 
                10, 10, 465, 230, hwnd, (HMENU)ID_TAB_CONTROL, hInst, NULL);
            SendMessage(hTab, WM_SETFONT, (WPARAM)hFont, TRUE);

            TCITEMW tie;
            tie.mask = TCIF_TEXT;
            tie.pszText = (LPWSTR)L"常规";
            TabCtrl_InsertItem(hTab, 0, &tie);
            tie.pszText = (LPWSTR)L"选项";
            TabCtrl_InsertItem(hTab, 1, &tie);

            // Create controls
            int startY = 45; // Inside/Below tab
            int y = startY;
            int labelW = 80;
            int editW = 300;
            int btnW = 60;
            int h = 25;
            int gap = 10;
            int x = 25;

            auto CreateLabel = [&](int id, const wchar_t* text, int row) {
                CreateWindowW(L"STATIC", text, WS_CHILD | WS_VISIBLE, x, y + row * (h + gap), labelW, h, hwnd, (HMENU)(UINT_PTR)id, hInst, NULL);
            };
            auto CreateEdit = [&](int id, const std::wstring& val, int row) {
                HWND hEdit = CreateWindowW(L"EDIT", val.c_str(), WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL, x + labelW, y + row * (h + gap), editW, h, hwnd, (HMENU)(UINT_PTR)id, hInst, NULL);
                SendMessage(hEdit, WM_SETFONT, (WPARAM)hFont, TRUE);
                return hEdit;
            };

            // --- Tab 0: General ---
            CreateLabel(ID_LABEL_NAME, L"服务名称:", 0);
            CreateEdit(ID_EDIT_NAME, g_dialogData.is_edit ? Utf8ToWide(g_manager.services[g_dialogData.service_index].name) : L"", 0);

            CreateLabel(ID_LABEL_TYPE, L"服务类型:", 1);
            HWND hCombo = CreateWindowW(L"COMBOBOX", L"", WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST, x + labelW, y + 1 * (h + gap), editW, 100, hwnd, (HMENU)ID_COMBO_TYPE, hInst, NULL);
            SendMessage(hCombo, WM_SETFONT, (WPARAM)hFont, TRUE);
            SendMessageW(hCombo, CB_ADDSTRING, 0, (LPARAM)L"python");
            SendMessageW(hCombo, CB_ADDSTRING, 0, (LPARAM)L"batch");
            SendMessageW(hCombo, CB_ADDSTRING, 0, (LPARAM)L"executable");
            std::wstring currentType = g_dialogData.is_edit ? Utf8ToWide(g_manager.services[g_dialogData.service_index].service_type) : L"python";
            int idx = SendMessageW(hCombo, CB_FINDSTRINGEXACT, -1, (LPARAM)currentType.c_str());
            SendMessage(hCombo, CB_SETCURSEL, (idx == CB_ERR ? 0 : idx), 0);

            CreateLabel(ID_LABEL_SCRIPT, L"脚本路径:", 2);
            CreateEdit(ID_EDIT_SCRIPT, g_dialogData.is_edit ? Utf8ToWide(g_manager.services[g_dialogData.service_index].script_path) : L"", 2);
            CreateWindowW(L"BUTTON", L"...", WS_CHILD | WS_VISIBLE, x + labelW + editW + 5, y + 2 * (h + gap), 30, h, hwnd, (HMENU)ID_BTN_BROWSE_SCRIPT, hInst, NULL);

            // Python路径标签使用ID，以便控制显示/隐藏
            CreateWindowW(L"STATIC", L"Python路径:", WS_CHILD | WS_VISIBLE, x, y + 3 * (h + gap), labelW, h, hwnd, (HMENU)ID_LABEL_PYTHON, hInst, NULL);
            CreateEdit(ID_EDIT_PYTHON, g_dialogData.is_edit ? Utf8ToWide(g_manager.services[g_dialogData.service_index].python_path) : L"", 3);
            CreateWindowW(L"BUTTON", L"...", WS_CHILD | WS_VISIBLE, x + labelW + editW + 5, y + 3 * (h + gap), 30, h, hwnd, (HMENU)ID_BTN_BROWSE_PYTHON, hInst, NULL);

            CreateLabel(ID_LABEL_ARGS, L"参数:", 4);
            CreateEdit(ID_EDIT_ARGS, g_dialogData.is_edit ? Utf8ToWide(g_manager.services[g_dialogData.service_index].args) : L"", 4);

            CreateLabel(ID_LABEL_WORKDIR, L"工作目录:", 5);
            CreateEdit(ID_EDIT_WORKDIR, g_dialogData.is_edit ? Utf8ToWide(g_manager.services[g_dialogData.service_index].work_dir) : L"", 5);
            CreateWindowW(L"BUTTON", L"...", WS_CHILD | WS_VISIBLE, x + labelW + editW + 5, y + 5 * (h + gap), 30, h, hwnd, (HMENU)ID_BTN_BROWSE_WORKDIR, hInst, NULL);

            // --- Tab 1: Daemon (Restart) ---
            // Re-use positions relative to top, but hide initially
            CreateWindowW(L"BUTTON", L"异常退出自动重启", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, x, startY, 200, h, hwnd, (HMENU)ID_CHECK_AUTORESTART, hInst, NULL);
            SendMessage(GetDlgItem(hwnd, ID_CHECK_AUTORESTART), BM_SETCHECK, g_dialogData.is_edit && g_manager.services[g_dialogData.service_index].auto_restart ? BST_CHECKED : BST_UNCHECKED, 0);
            ShowWindow(GetDlgItem(hwnd, ID_CHECK_AUTORESTART), SW_HIDE);

            CreateWindowW(L"BUTTON", L"自动启动", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, x, startY + 1 * (h + gap), 100, h, hwnd, (HMENU)ID_CHECK_AUTOSTART, hInst, NULL);
            SendMessage(GetDlgItem(hwnd, ID_CHECK_AUTOSTART), BM_SETCHECK, g_dialogData.is_edit && g_manager.services[g_dialogData.service_index].auto_start ? BST_CHECKED : BST_UNCHECKED, 0);
            ShowWindow(GetDlgItem(hwnd, ID_CHECK_AUTOSTART), SW_HIDE);

            CreateWindowW(L"BUTTON", L"隐藏控制台", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, x, startY + 2 * (h + gap), 100, h, hwnd, (HMENU)ID_CHECK_HIDECONSOLE, hInst, NULL);
            SendMessage(GetDlgItem(hwnd, ID_CHECK_HIDECONSOLE), BM_SETCHECK, g_dialogData.is_edit ? (g_manager.services[g_dialogData.service_index].hide_console ? BST_CHECKED : BST_UNCHECKED) : BST_CHECKED, 0);
            ShowWindow(GetDlgItem(hwnd, ID_CHECK_HIDECONSOLE), SW_HIDE);

            // Buttons (OK/Cancel) at bottom
            CreateWindowW(L"BUTTON", L"确定", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON, 150, 270, 80, 30, hwnd, (HMENU)ID_BTN_OK, hInst, NULL);
            CreateWindowW(L"BUTTON", L"取消", WS_CHILD | WS_VISIBLE, 250, 270, 80, 30, hwnd, (HMENU)ID_BTN_CANCEL, hInst, NULL);
            
            // Set font for all children
            EnumChildWindows(hwnd, [](HWND hChild, LPARAM lParam){
                SendMessage(hChild, WM_SETFONT, (WPARAM)lParam, TRUE);
                return TRUE;
            }, (LPARAM)hFont);

            // Handle initial visibility for General Tab
            bool isPython = (currentType == L"python");
            ShowWindow(GetDlgItem(hwnd, ID_LABEL_PYTHON), isPython ? SW_SHOW : SW_HIDE);
            ShowWindow(GetDlgItem(hwnd, ID_EDIT_PYTHON), isPython ? SW_SHOW : SW_HIDE);
            ShowWindow(GetDlgItem(hwnd, ID_BTN_BROWSE_PYTHON), isPython ? SW_SHOW : SW_HIDE);

            break;
        }
        case WM_NOTIFY: {
            LPNMHDR lpnm = (LPNMHDR)lParam;
            if (lpnm->idFrom == ID_TAB_CONTROL && lpnm->code == TCN_SELCHANGE) {
                int curSel = TabCtrl_GetCurSel(lpnm->hwndFrom);
                bool showGeneral = (curSel == 0);
                bool showDaemon = (curSel == 1);
                
                int generalIDs[] = {
                    ID_LABEL_NAME, ID_EDIT_NAME,
                    ID_LABEL_TYPE, ID_COMBO_TYPE,
                    ID_LABEL_SCRIPT, ID_EDIT_SCRIPT, ID_BTN_BROWSE_SCRIPT,
                    ID_LABEL_ARGS, ID_EDIT_ARGS,
                    ID_LABEL_WORKDIR, ID_EDIT_WORKDIR, ID_BTN_BROWSE_WORKDIR
                };
                
                for (int id : generalIDs) ShowWindow(GetDlgItem(hwnd, id), showGeneral ? SW_SHOW : SW_HIDE);

                // Python specific logic
                if (showGeneral) {
                    wchar_t buffer[256];
                    GetDlgItemTextW(hwnd, ID_COMBO_TYPE, buffer, 256);
                    bool isPython = (wcscmp(buffer, L"python") == 0);
                    ShowWindow(GetDlgItem(hwnd, ID_LABEL_PYTHON), isPython ? SW_SHOW : SW_HIDE);
                    ShowWindow(GetDlgItem(hwnd, ID_EDIT_PYTHON), isPython ? SW_SHOW : SW_HIDE);
                    ShowWindow(GetDlgItem(hwnd, ID_BTN_BROWSE_PYTHON), isPython ? SW_SHOW : SW_HIDE);
                } else {
                    ShowWindow(GetDlgItem(hwnd, ID_LABEL_PYTHON), SW_HIDE);
                    ShowWindow(GetDlgItem(hwnd, ID_EDIT_PYTHON), SW_HIDE);
                    ShowWindow(GetDlgItem(hwnd, ID_BTN_BROWSE_PYTHON), SW_HIDE);
                }

                // Daemon Tab
                ShowWindow(GetDlgItem(hwnd, ID_CHECK_AUTORESTART), showDaemon ? SW_SHOW : SW_HIDE);
                ShowWindow(GetDlgItem(hwnd, ID_CHECK_AUTOSTART), showDaemon ? SW_SHOW : SW_HIDE);
                ShowWindow(GetDlgItem(hwnd, ID_CHECK_HIDECONSOLE), showDaemon ? SW_SHOW : SW_HIDE);
            }
            break;
        }
        case WM_COMMAND: {
            int id = LOWORD(wParam);
            int code = HIWORD(wParam);

            if (id == ID_COMBO_TYPE && code == CBN_SELCHANGE) {
                HWND hCombo = (HWND)lParam;
                int idx = SendMessage(hCombo, CB_GETCURSEL, 0, 0);
                if (idx != CB_ERR) {
                    wchar_t buffer[256];
                    SendMessage(hCombo, CB_GETLBTEXT, idx, (LPARAM)buffer);
                    bool isPython = (wcscmp(buffer, L"python") == 0);
                    
                    // Only update if we are on General tab (which we must be to click the combo)
                    ShowWindow(GetDlgItem(hwnd, ID_LABEL_PYTHON), isPython ? SW_SHOW : SW_HIDE);
                    ShowWindow(GetDlgItem(hwnd, ID_EDIT_PYTHON), isPython ? SW_SHOW : SW_HIDE);
                    ShowWindow(GetDlgItem(hwnd, ID_BTN_BROWSE_PYTHON), isPython ? SW_SHOW : SW_HIDE);
                }
            }

            if (id == ID_BTN_OK) {
                wchar_t buffer[MAX_PATH];
                
                GetDlgItemTextW(hwnd, ID_EDIT_NAME, buffer, MAX_PATH);
                g_dialogData.result_service.name = WideToUtf8(buffer);
                
                GetDlgItemTextW(hwnd, ID_COMBO_TYPE, buffer, MAX_PATH);
                g_dialogData.result_service.service_type = WideToUtf8(buffer);
                
                GetDlgItemTextW(hwnd, ID_EDIT_SCRIPT, buffer, MAX_PATH);
                g_dialogData.result_service.script_path = WideToUtf8(buffer);
                
                GetDlgItemTextW(hwnd, ID_EDIT_PYTHON, buffer, MAX_PATH);
                g_dialogData.result_service.python_path = WideToUtf8(buffer);
                
                GetDlgItemTextW(hwnd, ID_EDIT_ARGS, buffer, MAX_PATH);
                g_dialogData.result_service.args = WideToUtf8(buffer);
                
                GetDlgItemTextW(hwnd, ID_EDIT_WORKDIR, buffer, MAX_PATH);
                g_dialogData.result_service.work_dir = WideToUtf8(buffer);
                
                g_dialogData.result_service.auto_start = (SendMessage(GetDlgItem(hwnd, ID_CHECK_AUTOSTART), BM_GETCHECK, 0, 0) == BST_CHECKED);
                g_dialogData.result_service.hide_console = (SendMessage(GetDlgItem(hwnd, ID_CHECK_HIDECONSOLE), BM_GETCHECK, 0, 0) == BST_CHECKED);
                g_dialogData.result_service.auto_restart = (SendMessage(GetDlgItem(hwnd, ID_CHECK_AUTORESTART), BM_GETCHECK, 0, 0) == BST_CHECKED);

                if (g_dialogData.result_service.name.empty() || g_dialogData.result_service.script_path.empty()) {
                    MessageBoxW(hwnd, L"名称和脚本路径不能为空", L"错误", MB_OK | MB_ICONERROR);
                    return 0;
                }

                DestroyWindow(hwnd);
            } else if (id == ID_BTN_CANCEL) {
                g_dialogData.result_service.name = ""; 
                DestroyWindow(hwnd);
            } else if (id == ID_BTN_BROWSE_SCRIPT || id == ID_BTN_BROWSE_PYTHON || id == ID_BTN_BROWSE_WORKDIR) {
                OPENFILENAMEW ofn;
                wchar_t szFile[MAX_PATH] = {0};
                ZeroMemory(&ofn, sizeof(ofn));
                ofn.lStructSize = sizeof(ofn);
                ofn.hwndOwner = hwnd;
                ofn.lpstrFile = szFile;
                ofn.nMaxFile = sizeof(szFile);

                ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

                if (id == ID_BTN_BROWSE_WORKDIR) {
                    // Folder picker is complex in pure Win32 without COM (IFileOpenDialog). 
                    // Fallback to simple file picker or just let user type.
                    // For simplicity in this code block, we'll skip folder picker implementation or use a hack.
                    // Let's just use file picker for now and strip filename, or rely on user typing.
                    // Actually, let's just show a message that they should type it or pick a file inside.
                    ofn.lpstrTitle = L"选择工作目录中的任意文件";
                } else {
                    ofn.lpstrFilter = L"All Files\0*.*\0Executable\0*.exe\0Python\0*.py\0Batch\0*.bat\0";
                }

                if (GetOpenFileNameW(&ofn)) {
                    if (id == ID_BTN_BROWSE_WORKDIR) {
                        std::wstring path = szFile;
                        size_t pos = path.find_last_of(L"\\/");
                        if (pos != std::wstring::npos) path = path.substr(0, pos);
                        // Convert to relative path
                        std::string absPath = WideToUtf8(path);
                        std::string relPath = g_manager.MakeRelativePath(absPath);
                        SetDlgItemTextW(hwnd, ID_EDIT_WORKDIR, Utf8ToWide(relPath).c_str());
                    } else if (id == ID_BTN_BROWSE_SCRIPT) {
                        // Convert to relative path
                        std::string absPath = WideToUtf8(szFile);
                        std::string relPath = g_manager.MakeRelativePath(absPath);
                        SetDlgItemTextW(hwnd, ID_EDIT_SCRIPT, Utf8ToWide(relPath).c_str());
                        // Auto set workdir if empty
                        wchar_t curWorkDir[MAX_PATH];
                        GetDlgItemTextW(hwnd, ID_EDIT_WORKDIR, curWorkDir, MAX_PATH);
                        if (wcslen(curWorkDir) == 0) {
                            std::wstring path = Utf8ToWide(absPath);
                            size_t pos = path.find_last_of(L"\\/");
                            if (pos != std::wstring::npos) path = path.substr(0, pos);
                            std::string workdirAbs = WideToUtf8(path);
                            std::string workdirRel = g_manager.MakeRelativePath(workdirAbs);
                            SetDlgItemTextW(hwnd, ID_EDIT_WORKDIR, Utf8ToWide(workdirRel).c_str());
                        }
                    } else {
                        // Convert to relative path
                        std::string absPath = WideToUtf8(szFile);
                        std::string relPath = g_manager.MakeRelativePath(absPath);
                        SetDlgItemTextW(hwnd, ID_EDIT_PYTHON, Utf8ToWide(relPath).c_str());
                    }
                }
            }
            break;
        }
        case WM_CLOSE:
            g_dialogData.result_service.name = ""; // Treat as cancel
            DestroyWindow(hwnd);
            break;
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

void ShowServiceDialog(HWND hParent, bool edit, int index = -1) {
    g_dialogData.is_edit = edit;
    g_dialogData.service_index = index;
    
    // Register Dialog Class
    WNDCLASSW wc = {0};
    wc.lpfnWndProc = DialogProc;
    wc.hInstance = hInst;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"ServiceDialogClass";
    RegisterClassW(&wc);

    HWND hDialog = CreateWindowExW(
        WS_EX_DLGMODALFRAME | WS_EX_TOPMOST,
        L"ServiceDialogClass",
        edit ? L"编辑服务" : L"添加服务",
        WS_VISIBLE | WS_SYSMENU | WS_CAPTION,
        CW_USEDEFAULT, CW_USEDEFAULT, 500, 350,
        hParent, NULL, hInst, NULL
    );

    // Disable parent
    EnableWindow(hParent, FALSE);

    // Message loop for dialog
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        if (msg.message == WM_NULL) { // Custom signal to close
             break; 
        }
        TranslateMessage(&msg);
        DispatchMessage(&msg);
        if (!IsWindow(hDialog)) break; // Dialog closed
    }

    EnableWindow(hParent, TRUE);
    SetForegroundWindow(hParent);
}

void ShowAboutDialog(HWND hParent) {
    static bool classRegistered = false;
    
    if (!classRegistered) {
        WNDCLASSW wc = {0};
        wc.lpfnWndProc = [](HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) -> LRESULT {
            static HWND hLinkText = NULL;
            switch (msg) {
                case WM_CREATE:
                    CreateWindowW(L"STATIC", L"Service Manager Tool v1.0\n版权所有 (c) 2025", WS_CHILD | WS_VISIBLE | SS_CENTER, 10, 20, 300, 40, hwnd, NULL, hInst, NULL);
                    hLinkText = CreateWindowW(L"STATIC", L"作者主页: https://github.com/git-howard", WS_CHILD | WS_VISIBLE | SS_CENTER | SS_NOTIFY, 10, 70, 300, 20, hwnd, (HMENU)ID_LINK_ABOUT, hInst, NULL);
                    CreateWindowW(L"BUTTON", L"确定", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON, 120, 110, 80, 30, hwnd, (HMENU)IDOK, hInst, NULL);
                    
                    // Set font
                    EnumChildWindows(hwnd, [](HWND hChild, LPARAM lParam){
                        SendMessage(hChild, WM_SETFONT, (WPARAM)lParam, TRUE);
                        return TRUE;
                    }, (LPARAM)hFont);
                    break;
                case WM_CTLCOLORSTATIC: {
                    HDC hdcStatic = (HDC)wParam;
                    HWND hStatic = (HWND)lParam;
                    if (hStatic == hLinkText) {
                        SetTextColor(hdcStatic, RGB(0, 0, 255));
                        SetBkMode(hdcStatic, TRANSPARENT);
                        return (LRESULT)GetStockObject(NULL_BRUSH);
                    }
                    break;
                }
                case WM_COMMAND:
                    if (LOWORD(wParam) == IDOK) {
                        DestroyWindow(hwnd);
                    } else if (LOWORD(wParam) == ID_LINK_ABOUT && HIWORD(wParam) == STN_CLICKED) {
                        ShellExecuteW(NULL, L"open", L"https://github.com/git-howard", NULL, NULL, SW_SHOWNORMAL);
                    }
                    break;
                case WM_CLOSE:
                    DestroyWindow(hwnd);
                    break;
                default:
                    return DefWindowProc(hwnd, msg, wParam, lParam);
            }
            return 0;
        };
        wc.hInstance = hInst;
        wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
        wc.lpszClassName = L"AboutDialogClass";
        wc.hCursor = LoadCursor(NULL, IDC_ARROW);
        RegisterClassW(&wc);
        classRegistered = true;
    }

    RECT rcOwner;
    GetWindowRect(hParent, &rcOwner);
    int dlgWidth = 340;
    int dlgHeight = 200;
    int x = rcOwner.left + (rcOwner.right - rcOwner.left - dlgWidth) / 2;
    int y = rcOwner.top + (rcOwner.bottom - rcOwner.top - dlgHeight) / 2;

    HWND hDialog = CreateWindowExW(WS_EX_DLGMODALFRAME | WS_EX_TOPMOST, L"AboutDialogClass", L"关于", WS_VISIBLE | WS_SYSMENU | WS_CAPTION, 
        x, y, dlgWidth, dlgHeight, hParent, NULL, hInst, NULL);
        
    EnableWindow(hParent, FALSE);
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        if (msg.message == WM_NULL) break;
        if (!IsWindow(hDialog)) break;
        if (!IsDialogMessage(hDialog, &msg)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }
    EnableWindow(hParent, TRUE);
    SetForegroundWindow(hParent);
}

// Tray Icon Functions
void InitTrayIcon(HWND hwnd) {
    ZeroMemory(&nid, sizeof(NOTIFYICONDATA));
    nid.cbSize = sizeof(NOTIFYICONDATA);
    nid.hWnd = hwnd;
    nid.uID = ID_TRAY_ICON;
    nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    nid.uCallbackMessage = WM_TRAYICON;
    nid.hIcon = LoadIcon(hInst, MAKEINTRESOURCE(101)); // Assuming 101 is the ID from resource
    if (!nid.hIcon) {
         // Fallback to loading from file if resource fails
         nid.hIcon = (HICON)LoadImage(NULL, L"service_manager.ico", IMAGE_ICON, 0, 0, LR_LOADFROMFILE | LR_DEFAULTSIZE);
    }
    if (!nid.hIcon) nid.hIcon = LoadIcon(NULL, IDI_APPLICATION); // Final fallback
    wcscpy_s(nid.szTip, L"程序管理器");
}

void ShowTrayIcon() {
    Shell_NotifyIcon(NIM_ADD, &nid);
}

void RemoveTrayIcon() {
    Shell_NotifyIcon(NIM_DELETE, &nid);
}

// Log Viewer Logic
LRESULT CALLBACK LogWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_SIZE: {
            HWND hEdit = GetDlgItem(hwnd, 100);
            RECT rc;
            GetClientRect(hwnd, &rc);
            MoveWindow(hEdit, 0, 0, rc.right, rc.bottom, TRUE);
            break;
        }
        case WM_CLOSE:
             DestroyWindow(hwnd);
             break;
        default:
            return DefWindowProc(hwnd, msg, wParam, lParam);
    }
    return 0;
}

std::string ReadFileRawWide(const std::wstring& wPath) {
    HANDLE hFile = CreateFileW(wPath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return "";
    std::string out;
    char buffer[4096];
    DWORD read = 0;
    while (ReadFile(hFile, buffer, sizeof(buffer), &read, NULL) && read > 0) out.append(buffer, buffer + read);
    CloseHandle(hFile);
    return out;
}

void ShowLogWindow(HWND hParent, const Service& svc) {
    static bool registered = false;
    if (!registered) {
        WNDCLASSW wc = {0};
        wc.lpfnWndProc = LogWndProc;
        wc.hInstance = hInst;
        wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
        wc.lpszClassName = L"LogWindow";
        wc.hCursor = LoadCursor(NULL, IDC_ARROW);
        RegisterClassW(&wc);
        registered = true;
    }

    std::wstring title = L"日志 - " + Utf8ToWide(svc.name);
    HWND hLogWnd = CreateWindowW(L"LogWindow", title.c_str(), WS_OVERLAPPEDWINDOW | WS_VISIBLE,
        CW_USEDEFAULT, CW_USEDEFAULT, 800, 600, hParent, NULL, hInst, NULL);

    HWND hEdit = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_READONLY,
        0, 0, 800, 600, hLogWnd, (HMENU)100, hInst, NULL);
    SendMessage(hEdit, WM_SETFONT, (WPARAM)hFont, TRUE);
    // Set max text limit
    SendMessage(hEdit, EM_SETLIMITTEXT, 0, 0); 
    std::string base = GetBasePath();
    std::vector<std::string> candidates;
    candidates.push_back(base + "\\logs\\" + svc.name + ".log");
    std::string workdir = svc.work_dir.empty() ? std::string("") : g_manager.resolve_path(svc.work_dir);
    if (!workdir.empty()) {
        candidates.push_back(workdir + "\\logs\\" + svc.name + ".log");
        candidates.push_back(workdir + "\\" + svc.name + ".log");
        // script dir
        std::string script = g_manager.resolve_path(svc.script_path);
        size_t pos = script.find_last_of("\\/");
        if (pos != std::string::npos) {
            std::string sdir = script.substr(0, pos);
            candidates.push_back(sdir + "\\logs\\" + svc.name + ".log");
        }
    }

    std::string content;
    std::wstring usedPathW;
    for (const auto& p : candidates) {
        std::wstring wp = Utf8ToWide(p);
        DWORD attrs = GetFileAttributesW(wp.c_str());
        if (attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY)) {
            content = ReadFileRawWide(wp);
            usedPathW = wp;
            break;
        }
    }
    if (content.empty()) {
        std::stringstream ss;
        ss << "无法找到日志文件于以下位置:\n";
        for (auto& p : candidates) ss << p << "\n";
        ss << "\n(服务可能从未运行过，或日志路径不在默认位置)";
        content = ss.str();
    }
    
    std::wstring wContent = Utf8ToWide(content);
    std::wstring wContentFixed;
    // Normalize line endings to \r\n for Edit control
    for (size_t i = 0; i < wContent.length(); ++i) {
        if (wContent[i] == L'\n' && (i == 0 || wContent[i-1] != L'\r')) {
            wContentFixed += L"\r\n";
        } else {
            wContentFixed += wContent[i];
        }
    }

    SetWindowTextW(hEdit, wContentFixed.c_str());
    
    // Scroll to end
    int len = GetWindowTextLength(hEdit);
    SendMessage(hEdit, EM_SETSEL, len, len);
    SendMessage(hEdit, EM_SCROLLCARET, 0, 0);
}

// Main Window Logic
void UpdateListView() {
    g_manager.check_status();
    ListView_DeleteAllItems(hListView);

    for (size_t i = 0; i < g_manager.services.size(); ++i) {
        Service& s = g_manager.services[i];
        
        LVITEMW lvItem = {0};
        lvItem.mask = LVIF_TEXT | LVIF_PARAM;
        lvItem.iItem = (int)i;
        lvItem.lParam = (LPARAM)i;
        
        std::wstring wName = Utf8ToWide(s.name);
        lvItem.pszText = (LPWSTR)wName.c_str();
        ListView_InsertItem(hListView, &lvItem);

        std::wstring wStatus = Utf8ToWide(s.status);
        ListView_SetItemText(hListView, i, 1, (LPWSTR)wStatus.c_str());

        std::wstring wPid = s.pid ? std::to_wstring(s.pid) : L"";
        ListView_SetItemText(hListView, i, 2, (LPWSTR)wPid.c_str());

        std::wstring wType = Utf8ToWide(s.service_type);
        ListView_SetItemText(hListView, i, 3, (LPWSTR)wType.c_str());

        std::wstring wAutoStart = s.auto_start ? L"是" : L"否";
        ListView_SetItemText(hListView, i, 4, (LPWSTR)wAutoStart.c_str());

        std::wstring wHideConsole = s.hide_console ? L"是" : L"否";
        ListView_SetItemText(hListView, i, 5, (LPWSTR)wHideConsole.c_str());

        std::wstring wAutoRestart = s.auto_restart ? L"是" : L"否";
        ListView_SetItemText(hListView, i, 6, (LPWSTR)wAutoRestart.c_str());

        std::wstring wRuntime = Utf8ToWide(s.get_runtime());
        ListView_SetItemText(hListView, i, 7, (LPWSTR)wRuntime.c_str());

        std::wstring wPorts = Utf8ToWide(s.ports);
        ListView_SetItemText(hListView, i, 8, (LPWSTR)wPorts.c_str());
    }
}

// Service Globals
SERVICE_STATUS g_ServiceStatus = {0};
SERVICE_STATUS_HANDLE g_StatusHandle = NULL;
HANDLE g_ServiceStopEvent = INVALID_HANDLE_VALUE;

void WINAPI ServiceCtrlHandler(DWORD dwControl) {
    switch (dwControl) {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            if (g_ServiceStatus.dwCurrentState != SERVICE_RUNNING) break;
            
            g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
            SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
            
            SetEvent(g_ServiceStopEvent);
            break;
        case 128: // Custom code for Config Reload
            g_manager.load_config();
            // Optional: Start new auto-start services that are not running?
            // For now, just reload so next check/action uses new config.
            break;
        default:
            break;
    }
}

void WINAPI ServiceMain(DWORD argc, LPTSTR *argv) {
    g_StatusHandle = RegisterServiceCtrlHandlerW(L"ServiceManager", ServiceCtrlHandler);
    if (!g_StatusHandle) return;

    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    g_ServiceStatus.dwWin32ExitCode = 0;
    g_ServiceStatus.dwServiceSpecificExitCode = 0;
    g_ServiceStatus.dwCheckPoint = 0;
    g_ServiceStatus.dwWaitHint = 0;

    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    g_ServiceStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!g_ServiceStopEvent) {
        g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
        return;
    }

    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    // Service Logic
    // Use global manager
    g_manager.load_config();
    
    for (size_t i = 0; i < g_manager.services.size(); ++i) {
        if (g_manager.services[i].auto_start) {
            g_manager.start_service(i);
        }
    }

    WaitForSingleObject(g_ServiceStopEvent, INFINITE);

    g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    // Stop all services
    for (size_t i = 0; i < g_manager.services.size(); ++i) {
        g_manager.stop_service(i);
    }

    CloseHandle(g_ServiceStopEvent);
    g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
}

void InstallService() {
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);
    std::string binPath = std::string(path) + " --service"; // Add flag
    std::string cmd = "create ServiceManager binPath= \"" + binPath + "\" start= auto DisplayName= \"Service Manager Tool\"";
    
    SHELLEXECUTEINFOA sei = { sizeof(sei) };
    sei.lpVerb = "runas";
    sei.lpFile = "sc";
    sei.lpParameters = cmd.c_str();
    sei.nShow = SW_HIDE;
    
    if (ShellExecuteExA(&sei)) {
        MessageBoxW(NULL, L"服务注册命令已发送", L"提示", MB_OK);
    } else {
        MessageBoxW(NULL, L"无法执行服务注册命令", L"错误", MB_OK | MB_ICONERROR);
    }
}

void UninstallService() {
    SHELLEXECUTEINFOA sei = { sizeof(sei) };
    sei.lpVerb = "runas";
    sei.lpFile = "sc";
    sei.lpParameters = "delete ServiceManager";
    sei.nShow = SW_HIDE;
    
    if (ShellExecuteExA(&sei)) {
        MessageBoxW(NULL, L"服务删除命令已发送", L"提示", MB_OK);
    } else {
        MessageBoxW(NULL, L"无法执行服务删除命令", L"错误", MB_OK | MB_ICONERROR);
    }
}

void InstallAndStartService() {
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);
    std::string binPath = std::string(path) + " --service";
    std::string cmdCreate = "create ServiceManager binPath= \"" + binPath + "\" start= auto DisplayName= \"Service Manager Tool\"";
    SHELLEXECUTEINFOA sei1 = { sizeof(sei1) };
    sei1.lpVerb = "runas";
    sei1.lpFile = "sc";
    sei1.lpParameters = cmdCreate.c_str();
    sei1.nShow = SW_HIDE;
    ShellExecuteExA(&sei1);

    SHELLEXECUTEINFOA sei2 = { sizeof(sei2) };
    sei2.lpVerb = "runas";
    sei2.lpFile = "sc";
    sei2.lpParameters = "start ServiceManager";
    sei2.nShow = SW_HIDE;
    ShellExecuteExA(&sei2);
}

void StopAndDeleteService() {
    SHELLEXECUTEINFOA sei1 = { sizeof(sei1) };
    sei1.lpVerb = "runas";
    sei1.lpFile = "sc";
    sei1.lpParameters = "stop ServiceManager";
    sei1.nShow = SW_HIDE;
    ShellExecuteExA(&sei1);

    SHELLEXECUTEINFOA sei2 = { sizeof(sei2) };
    sei2.lpVerb = "runas";
    sei2.lpFile = "sc";
    sei2.lpParameters = "delete ServiceManager";
    sei2.nShow = SW_HIDE;
    ShellExecuteExA(&sei2);
}

void StartSystemService() {
    SHELLEXECUTEINFOA sei = { sizeof(sei) };
    sei.lpVerb = "runas";
    sei.lpFile = "sc";
    sei.lpParameters = "start ServiceManager";
    sei.nShow = SW_HIDE;
    ShellExecuteExA(&sei);
}

void StopSystemService() {
    SHELLEXECUTEINFOA sei = { sizeof(sei) };
    sei.lpVerb = "runas";
    sei.lpFile = "sc";
    sei.lpParameters = "stop ServiceManager";
    sei.nShow = SW_HIDE;
    ShellExecuteExA(&sei);
}

void RestartSystemService() {
    StopSystemService();
    Sleep(800);
    StartSystemService();
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE: {
            // Load Icon
            HICON hIcon = LoadIcon(hInst, MAKEINTRESOURCE(101)); // Try to load from resource first
            if (!hIcon) {
                 // Try loading from file if resource fails (though resource is preferred)
                 hIcon = (HICON)LoadImage(NULL, L"service_manager.ico", IMAGE_ICON, 0, 0, LR_LOADFROMFILE | LR_DEFAULTSIZE);
            }
            if (hIcon) {
                SendMessage(hwnd, WM_SETICON, ICON_BIG, (LPARAM)hIcon);
                SendMessage(hwnd, WM_SETICON, ICON_SMALL, (LPARAM)hIcon);
            }

            EnableModernWindow(hwnd);
            InitTrayIcon(hwnd);

            // ListView height reduced to 240 to show ~10 rows
            hListView = CreateWindowExW(0, WC_LISTVIEWW, L"", 
                WS_CHILD | WS_VISIBLE | WS_BORDER | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
                10, 10, 760, 240, hwnd, (HMENU)ID_LISTVIEW, hInst, NULL);
            
            ListView_SetExtendedListViewStyle(hListView, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
            SetWindowTheme(hListView, L"Explorer", NULL);
            // 默认文本颜色设为高对比深色
            SendMessageW(hListView, LVM_SETTEXTCOLOR, 0, (LPARAM)RGB(32,32,32));
            SendMessageW(hListView, LVM_SETBKCOLOR, 0, (LPARAM)RGB(255,255,255));
            
            LVCOLUMNW lvc = {0};
            lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;
            lvc.fmt = LVCFMT_LEFT;
            
            lvc.cx = 150; lvc.pszText = (LPWSTR)L"服务名称"; ListView_InsertColumn(hListView, 0, &lvc);
            lvc.cx = 50; lvc.pszText = (LPWSTR)L"状态"; ListView_InsertColumn(hListView, 1, &lvc);
            lvc.cx = 48;  lvc.pszText = (LPWSTR)L"PID"; ListView_InsertColumn(hListView, 2, &lvc);
            lvc.cx = 70; lvc.pszText = (LPWSTR)L"类型"; ListView_InsertColumn(hListView, 3, &lvc);
            
            lvc.fmt = LVCFMT_CENTER;
            lvc.cx = 48;  lvc.pszText = (LPWSTR)L"自启动"; ListView_InsertColumn(hListView, 4, &lvc);
            lvc.cx = 48;  lvc.pszText = (LPWSTR)L"隐藏"; ListView_InsertColumn(hListView, 5, &lvc);
            lvc.cx = 48;  lvc.pszText = (LPWSTR)L"重启"; ListView_InsertColumn(hListView, 6, &lvc);
            
            lvc.fmt = LVCFMT_LEFT;
            lvc.cx = 60; lvc.pszText = (LPWSTR)L"运行时间"; ListView_InsertColumn(hListView, 7, &lvc);
            lvc.cx = 225; lvc.pszText = (LPWSTR)L"系统TCP端口"; ListView_InsertColumn(hListView, 8, &lvc);

            // Create Log Edit Control (lower section)
            hLogEdit = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY | WS_VSCROLL,
                10, 260, 760, 150, hwnd, (HMENU)ID_EDIT_LOG, hInst, NULL);
            SendMessage(hLogEdit, WM_SETFONT, (WPARAM)hFont, TRUE);

            // Create Buttons
            int btnY = 420;
            int btnH = 30;
            int btnW = 81;
            int gap = 10;
            int x = 10;

            auto CreateBtn = [&](int id, const wchar_t* text) {
                HWND hBtn = CreateWindowW(L"BUTTON", text, WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, x, btnY, btnW, btnH, hwnd, (HMENU)(UINT_PTR)id, hInst, NULL);
                SendMessage(hBtn, WM_SETFONT, (WPARAM)hFont, TRUE);
                x += btnW + gap;
            };

            CreateBtn(ID_BTN_ADD, L"添加服务");
            CreateBtn(ID_BTN_EDIT, L"编辑服务");
            CreateBtn(ID_BTN_DEL, L"删除服务");
            x += gap; // Extra gap
            // Removed Start/Stop individual buttons as requested
            CreateBtn(ID_BTN_STARTALL, L"全部启动");
            CreateBtn(ID_BTN_STOPALL, L"全部停止");
            CreateBtn(ID_BTN_TRAY, L"到托盘");
            CreateBtn(ID_BTN_SYSTEM_SERVICE, L"系统服务");

            // ? Button
            HWND hBtnAbout = CreateWindowW(L"BUTTON", L"?", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, x, btnY, 30, btnH, hwnd, (HMENU)ID_BTN_ABOUT, hInst, NULL);
            SendMessage(hBtnAbout, WM_SETFONT, (WPARAM)hFont, TRUE);

            // Author Link
            CreateWindowW(WC_LINK, L"作者主页: <a href=\"https://github.com/git-howard\">https://github.com/git-howard</a>", 
                WS_CHILD | WS_VISIBLE | WS_TABSTOP, 
                10, 460, 400, 20, hwnd, (HMENU)ID_LINK_AUTHOR, hInst, NULL);

            // Timer for updates
            SetTimer(hwnd, ID_TIMER_UPDATE, 1000, NULL);

            // Initial Load
            g_manager.load_config();
            
            // Auto-start services
            std::vector<std::string> autoStartServices;
            for (const auto& svc : g_manager.services) {
                if (svc.auto_start) {
                    autoStartServices.push_back(svc.name);
                }
            }
            
            if (!autoStartServices.empty()) {
                std::thread(StartupThreadFunc, hwnd, autoStartServices, g_manager.startup_interval).detach();
            }
            
            UpdateListView();

            // Add "About" to System Menu
            HMENU hSysMenu = GetSystemMenu(hwnd, FALSE);
            AppendMenuW(hSysMenu, MF_SEPARATOR, 0, NULL);
            AppendMenuW(hSysMenu, MF_STRING, IDM_ABOUT, L"关于 (&A)...");
                return 0;
            }
            if ((wParam & 0xFFF0) == IDM_ABOUT) {
                ShowAboutDialog(hwnd);
                return 0;
            }
            return DefWindowProc(hwnd, msg, wParam, lParam);
        case WM_REQ_START_FROM_QUEUE: {
            std::string name;
            {
                std::lock_guard<std::mutex> lock(g_pendingMutex);
                if (!g_pendingStarts.empty()) {
                    name = g_pendingStarts.front();
                    g_pendingStarts.pop_front();
                }
            }
            
            if (!name.empty()) {
                int idx = g_manager.get_service_index(name);
                if (idx != -1) {
                    g_manager.start_service(idx);
                    UpdateListView();
                }
            }
            break;
        }
        case WM_TRAYICON:
            if (lParam == WM_RBUTTONUP) {
                POINT pt;
                GetCursorPos(&pt);
                HMENU hMenu = CreatePopupMenu();
                AppendMenuW(hMenu, MF_STRING, ID_TRAY_RESTORE, L"显示窗口");
                AppendMenuW(hMenu, MF_STRING, ID_TRAY_EXIT, L"退出");
                SetForegroundWindow(hwnd);
                TrackPopupMenu(hMenu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, NULL);
                DestroyMenu(hMenu);
            } else if (lParam == WM_LBUTTONDBLCLK) {
                ShowWindow(hwnd, SW_SHOW);
                ShowWindow(hwnd, SW_RESTORE);
                RemoveTrayIcon();
                isMinimizedToTray = false;
                SetForegroundWindow(hwnd);
            }
            break;
        case WM_TIMER:
            if (wParam == ID_TIMER_UPDATE) {
                // Update status without full redraw if possible, but for simplicity we reload
                // To avoid flickering, we should optimize, but for now simple update
                // We only update status columns to avoid selection loss
                g_manager.check_status();
                for (size_t i = 0; i < g_manager.services.size(); ++i) {
                    Service& s = g_manager.services[i];
                    std::wstring wStatus = Utf8ToWide(s.status);
                    std::wstring wPid = s.pid ? std::to_wstring(s.pid) : L"";
                    std::wstring wRuntime = Utf8ToWide(s.get_runtime());
                    std::wstring wPorts = Utf8ToWide(s.ports);
                    
                    // Helper lambda to check and update
                    auto updateIfChanged = [&](int col, const std::wstring& newVal) {
                        wchar_t buf[256];
                        ListView_GetItemText(hListView, i, col, buf, 256);
                        if (newVal != buf) {
                            ListView_SetItemText(hListView, i, col, (LPWSTR)newVal.c_str());
                        }
                    };

                    updateIfChanged(1, wStatus);
                    updateIfChanged(2, wPid);
                    updateIfChanged(7, wRuntime);
                    updateIfChanged(8, wPorts);
                }
            }
            break;
        case WM_NOTIFY: {
            LPNMHDR lpnm = (LPNMHDR)lParam;
            if (lpnm->idFrom == ID_LISTVIEW && lpnm->code == NM_CUSTOMDRAW) {
                LPNMLVCUSTOMDRAW cd = (LPNMLVCUSTOMDRAW)lParam;
                switch (cd->nmcd.dwDrawStage) {
                case CDDS_PREPAINT: return CDRF_NOTIFYITEMDRAW;
                case CDDS_ITEMPREPAINT: return CDRF_NOTIFYSUBITEMDRAW;
                case CDDS_SUBITEM | CDDS_ITEMPREPAINT: {
                    auto isHighContrast = [](){
                        HIGHCONTRASTW hc{sizeof(hc)};
                        return SystemParametersInfoW(SPI_GETHIGHCONTRAST, sizeof(hc), &hc, 0) && (hc.dwFlags & HCF_HIGHCONTRASTON);
                    }();
                    if (cd->nmcd.uItemState & CDIS_SELECTED) {
                        RECT rc; ListView_GetSubItemRect((HWND)cd->nmcd.hdr.hwndFrom, (int)cd->nmcd.dwItemSpec, cd->iSubItem, LVIR_BOUNDS, &rc);
                        if (isHighContrast) {
                            HBRUSH br = CreateSolidBrush(GetSysColor(COLOR_HIGHLIGHT));
                            FillRect(cd->nmcd.hdc, &rc, br);
                            DeleteObject(br);
                            cd->clrText = GetSysColor(COLOR_HIGHLIGHTTEXT);
                            cd->clrTextBk = CLR_NONE;
                            return CDRF_NEWFONT;
                        } else {
                            TRIVERTEX vx[2] = { {rc.left,rc.top,0x04F8,0x09FD,0x0FFE,0x0000},
                                                {rc.right,rc.bottom,0x03E6,0x08CB,0x0FFE,0x0000} };
                            GRADIENT_RECT gr = {0,1};
                            GradientFill(cd->nmcd.hdc, vx, 2, &gr, 1, GRADIENT_FILL_RECT_H);
                            cd->clrText = RGB(255,255,255);
                            cd->clrTextBk = CLR_NONE;
                            return CDRF_NEWFONT;
                        }
                    } else {
                        // Uniform white background and black text
                        cd->clrTextBk = isHighContrast ? GetSysColor(COLOR_WINDOW) : RGB(255, 255, 255);
                        cd->clrText = isHighContrast ? GetSysColor(COLOR_WINDOWTEXT) : RGB(0, 0, 0);
                        return CDRF_NEWFONT;
                    }
                    break;
                }
                }
            }
            if (lpnm->idFrom == ID_LISTVIEW && lpnm->code == NM_RCLICK) {
                LPNMITEMACTIVATE lpnmitem = (LPNMITEMACTIVATE)lParam;
                if (lpnmitem->iItem != -1) {
                    // Select the item first
                    ListView_SetItemState(hListView, lpnmitem->iItem, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
                    
                    HMENU hMenu = CreatePopupMenu();
                    Service& s = g_manager.services[lpnmitem->iItem];
                    
                    bool running = (s.status == "运行中");
                    
                    AppendMenuW(hMenu, MF_STRING | (running ? MF_GRAYED : 0), ID_MENU_START, L"启动");
                    AppendMenuW(hMenu, MF_STRING | (!running ? MF_GRAYED : 0), ID_MENU_STOP, L"停止");
                    AppendMenuW(hMenu, MF_STRING | (!running ? MF_GRAYED : 0), ID_MENU_RESTART, L"重启");
                    AppendMenuW(hMenu, MF_SEPARATOR, 0, NULL);
                    AppendMenuW(hMenu, MF_STRING, ID_MENU_LOG, L"查看日志");
                    AppendMenuW(hMenu, MF_SEPARATOR, 0, NULL);
                    AppendMenuW(hMenu, MF_STRING, ID_MENU_EDIT, L"编辑");
                    AppendMenuW(hMenu, MF_STRING, ID_MENU_DEL, L"删除");
                    AppendMenuW(hMenu, MF_SEPARATOR, 0, NULL);
                    AppendMenuW(hMenu, MF_STRING | (lpnmitem->iItem == 0 ? MF_GRAYED : 0), ID_MENU_MOVE_UP, L"上移");
                    AppendMenuW(hMenu, MF_STRING | (lpnmitem->iItem == g_manager.services.size() - 1 ? MF_GRAYED : 0), ID_MENU_MOVE_DOWN, L"下移");
                    
                    POINT pt;
                    GetCursorPos(&pt);
                    TrackPopupMenu(hMenu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, NULL);
                    DestroyMenu(hMenu);
                }
            } else if (lpnm->idFrom == ID_LINK_AUTHOR && (lpnm->code == NM_CLICK || lpnm->code == NM_RETURN)) {
                PNMLINK pNMLink = (PNMLINK)lParam;
                ShellExecuteW(NULL, L"open", pNMLink->item.szUrl, NULL, NULL, SW_SHOWNORMAL);
            }
            break;
        }
        case WM_COMMAND: {
            int id = LOWORD(wParam);
            switch (id) {
                case ID_BTN_ADD:
                    ShowServiceDialog(hwnd, false);
                    if (!g_dialogData.result_service.name.empty()) {
                        g_manager.services.push_back(g_dialogData.result_service);
                        g_manager.save_config();
                        UpdateListView();
                        // Clear for next time
                        g_dialogData.result_service = Service();
                    }
                    break;
                case ID_BTN_EDIT: {
                    int sel = ListView_GetNextItem(hListView, -1, LVNI_SELECTED);
                    if (sel != -1) {
                        ShowServiceDialog(hwnd, true, sel);
                        if (!g_dialogData.result_service.name.empty()) {
                            // Keep runtime status if name didn't change? 
                            // For simplicity, we just update config fields
                            Service& s = g_manager.services[sel];
                            s.name = g_dialogData.result_service.name;
                            s.service_type = g_dialogData.result_service.service_type;
                            s.script_path = g_dialogData.result_service.script_path;
                            s.python_path = g_dialogData.result_service.python_path;
                            s.args = g_dialogData.result_service.args;
                            s.work_dir = g_dialogData.result_service.work_dir;
                            s.auto_start = g_dialogData.result_service.auto_start;
                            s.hide_console = g_dialogData.result_service.hide_console;
                            s.auto_restart = g_dialogData.result_service.auto_restart;
                            
                            g_manager.save_config();
                            UpdateListView();
                            g_dialogData.result_service = Service();
                        }
                    } else {
                        MessageBoxW(hwnd, L"请先选择一个服务", L"提示", MB_OK);
                    }
                    break;
                }
                case ID_BTN_DEL: {
                    int sel = ListView_GetNextItem(hListView, -1, LVNI_SELECTED);
                    if (sel != -1) {
                        if (MessageBoxW(hwnd, L"确定要删除该服务吗？", L"确认", MB_YESNO | MB_ICONQUESTION) == IDYES) {
                            if (g_manager.services[sel].status == "运行中") {
                                g_manager.stop_service(sel);
                            }
                            g_manager.services.erase(g_manager.services.begin() + sel);
                            g_manager.save_config();
                            UpdateListView();
                        }
                    }
                    break;
                }
                case ID_BTN_START: {
                    int sel = ListView_GetNextItem(hListView, -1, LVNI_SELECTED);
                    if (sel != -1) {
                        g_manager.start_service(sel);
                        UpdateListView();
                    }
                    break;
                }
                case ID_BTN_STOP: {
                    int sel = ListView_GetNextItem(hListView, -1, LVNI_SELECTED);
                    if (sel != -1) {
                        g_manager.stop_service(sel);
                        UpdateListView();
                    }
                    break;
                }
                case ID_BTN_STARTALL: {
                    std::vector<std::string> allServices;
                    for (const auto& svc : g_manager.services) {
                        allServices.push_back(svc.name);
                    }
                    if (!allServices.empty()) {
                        std::thread(StartupThreadFunc, hwnd, allServices, g_manager.startup_interval).detach();
                    }
                    UpdateListView();
                    break;
                }
                case ID_BTN_STOPALL:
                    for (size_t i = 0; i < g_manager.services.size(); ++i) g_manager.stop_service(i);
                    UpdateListView();
                    break;
                case ID_BTN_TRAY:
                    AnimateWindow(hwnd, 150, AW_BLEND | AW_HIDE);
                    ShowTrayIcon();
                    isMinimizedToTray = true;
                    break;
                case ID_BTN_SYSTEM_SERVICE: {
                    HWND hBtn = GetDlgItem(hwnd, ID_BTN_SYSTEM_SERVICE);
                    RECT rc; GetWindowRect(hBtn, &rc);
                    HMENU hMenu = CreatePopupMenu();
                    AppendMenuW(hMenu, MF_STRING, ID_MENU_SYS_INSTALL_START, L"注册并启动服务");
                    AppendMenuW(hMenu, MF_STRING, ID_MENU_SYS_STOP_DELETE, L"停止并注销服务");
                    AppendMenuW(hMenu, MF_SEPARATOR, 0, NULL);
                    AppendMenuW(hMenu, MF_STRING, ID_MENU_SYS_START, L"启动服务");
                    AppendMenuW(hMenu, MF_STRING, ID_MENU_SYS_STOP, L"停止服务");
                    AppendMenuW(hMenu, MF_STRING, ID_MENU_SYS_RESTART, L"重启服务");
                    TrackPopupMenu(hMenu, TPM_LEFTALIGN | TPM_TOPALIGN, rc.left, rc.bottom, 0, hwnd, NULL);
                    DestroyMenu(hMenu);
                    break;
                }
                case ID_MENU_SYS_INSTALL_START:
                    InstallAndStartService();
                    break;
                case ID_MENU_SYS_STOP_DELETE:
                    StopAndDeleteService();
                    break;
                case ID_MENU_SYS_START:
                    StartSystemService();
                    break;
                case ID_MENU_SYS_STOP:
                    StopSystemService();
                    break;
                case ID_MENU_SYS_RESTART:
                    RestartSystemService();
                    break;
                case ID_MENU_MOVE_UP: {
                    int sel = ListView_GetNextItem(hListView, -1, LVNI_SELECTED);
                    if (sel > 0) {
                        std::swap(g_manager.services[sel], g_manager.services[sel - 1]);
                        g_manager.save_config();
                        UpdateListView();
                        // Restore selection
                        ListView_SetItemState(hListView, sel - 1, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
                        ListView_EnsureVisible(hListView, sel - 1, FALSE);
                    }
                    break;
                }
                case ID_MENU_MOVE_DOWN: {
                    int sel = ListView_GetNextItem(hListView, -1, LVNI_SELECTED);
                    if (sel != -1 && sel < g_manager.services.size() - 1) {
                        std::swap(g_manager.services[sel], g_manager.services[sel + 1]);
                        g_manager.save_config();
                        UpdateListView();
                        // Restore selection
                        ListView_SetItemState(hListView, sel + 1, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
                        ListView_EnsureVisible(hListView, sel + 1, FALSE);
                    }
                    break;
                }
                case ID_MENU_START:
                    SendMessage(hwnd, WM_COMMAND, ID_BTN_START, 0);
                    break;
                case ID_MENU_STOP:
                    SendMessage(hwnd, WM_COMMAND, ID_BTN_STOP, 0);
                    break;
                case ID_MENU_RESTART: {
                    int sel = ListView_GetNextItem(hListView, -1, LVNI_SELECTED);
                    if (sel != -1) {
                        if (g_manager.services[sel].status == "运行中") {
                            g_manager.stop_service(sel);
                        }
                        g_manager.start_service(sel);
                        UpdateListView();
                    }
                    break;
                }
                case ID_MENU_LOG: {
                    int sel = ListView_GetNextItem(hListView, -1, LVNI_SELECTED);
                    if (sel != -1) {
                        ShowLogWindow(hwnd, g_manager.services[sel]);
                    }
                    break;
                }
                case ID_MENU_EDIT:
                    SendMessage(hwnd, WM_COMMAND, ID_BTN_EDIT, 0);
                    break;
                case ID_MENU_DEL:
                    SendMessage(hwnd, WM_COMMAND, ID_BTN_DEL, 0);
                    break;
                case ID_TRAY_RESTORE:
                    ShowWindow(hwnd, SW_SHOW);
                    AnimateWindow(hwnd, 150, AW_BLEND);
                    RemoveTrayIcon();
                    isMinimizedToTray = false;
                    SetForegroundWindow(hwnd);
                    break;
                case ID_TRAY_EXIT:
                    SendMessage(hwnd, WM_CLOSE, 0, 0);
                    break;
                case ID_BTN_ABOUT:
                    ShowAboutDialog(hwnd);
                    break;
            }
            break;
        }
        case WM_DRAWITEM: {
            DRAWITEMSTRUCT* p = (DRAWITEMSTRUCT*)lParam;
            if (p->CtlType == ODT_BUTTON) {
                RECT rc = p->rcItem;
                BOOL press = (p->itemState & ODS_SELECTED) != 0;
                BOOL focus = (p->itemState & ODS_FOCUS) != 0;
                COLORREF base = RGB(0x00,0x78,0xD4);
                COLORREF fill = press ? RGB(0x0F,0x6C,0xBD) : base;
                HBRUSH br = CreateSolidBrush(fill);
                HPEN pen = CreatePen(PS_SOLID, 1, RGB(0x00,0x5A,0x9E));
                HGDIOBJ oldPen = SelectObject(p->hDC, pen);
                HGDIOBJ oldBr = SelectObject(p->hDC, br);
                RoundRect(p->hDC, rc.left, rc.top, rc.right, rc.bottom, 8, 8);
                SelectObject(p->hDC, oldBr); DeleteObject(br);
                SelectObject(p->hDC, oldPen); DeleteObject(pen);
                SetBkMode(p->hDC, TRANSPARENT);
                SetTextColor(p->hDC, RGB(255,255,255));
                wchar_t textBuf[128];
                SendMessage((HWND)p->hwndItem, WM_GETTEXT, (WPARAM)128, (LPARAM)textBuf);
                DrawTextW(p->hDC, textBuf, -1, &rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
                if (focus) {
                    DrawFocusRect(p->hDC, &rc);
                }
                return TRUE;
            }
            break;
        }
        case WM_CLOSE:
            if (!isMinimizedToTray && !IsSystemServiceRunning()) {
                bool anyRunning = false;
                for (const auto& svc : g_manager.services) {
                    if (svc.status == "运行中") {
                        anyRunning = true;
                        break;
                    }
                }
                
                if (anyRunning) {
                    if (MessageBoxW(hwnd, L"系统服务未运行，关闭窗口将停止所有正在运行的服务。\n是否确认退出？", L"确认退出", MB_YESNO | MB_ICONWARNING) != IDYES) {
                        return 0;
                    }
                }
            }
            DestroyWindow(hwnd);
            break;
        case WM_DESTROY:
            RemoveTrayIcon();
            // If System Service is NOT running, we are in standalone mode, so stop services.
            // If System Service IS running, we leave them alone (handled by service).
            if (!IsSystemServiceRunning()) {
                for (size_t i = 0; i < g_manager.services.size(); ++i) g_manager.stop_service(i);
            }
            PostQuitMessage(0);
            break;
        default:
            return DefWindowProc(hwnd, msg, wParam, lParam);
    }
    return 0;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    // Check if running as service
    if (strstr(lpCmdLine, "--service")) {
        SERVICE_TABLE_ENTRYW ServiceTable[] = {
            { (LPWSTR)L"ServiceManager", (LPSERVICE_MAIN_FUNCTIONW)ServiceMain },
            { NULL, NULL }
        };
        StartServiceCtrlDispatcherW(ServiceTable);
        return 0;
    }

    // GUI Mode
    // Check for existing GUI instance
    HANDLE hMutex = CreateMutexW(NULL, TRUE, L"Global\\ServiceManagerGUIMutex");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        HWND hExistingWnd = FindWindowW(L"ServiceManagerClass", NULL);
        if (hExistingWnd) {
            // If hidden (tray), show it
            ShowWindow(hExistingWnd, SW_SHOW);
            ShowWindow(hExistingWnd, SW_RESTORE);
            SetForegroundWindow(hExistingWnd);
        }
        return 0;
    }

    hInst = hInstance;
    
    // Set environment variables for Python UTF-8 support
    _wputenv(L"PYTHONIOENCODING=utf-8");
    _wputenv(L"PYTHONLEGACYWINDOWSSTDIO=utf-8");
    
    // Initialize Common Controls
    INITCOMMONCONTROLSEX icex;
    icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
    icex.dwICC = ICC_LISTVIEW_CLASSES | ICC_LINK_CLASS;
    InitCommonControlsEx(&icex);

    // Create Font
    hFont = CreateFontW(16, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Microsoft YaHei");

    // Register Window Class
    WNDCLASSW wc = {0};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"ServiceManagerClass";
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    
    // Load Icon
    wc.hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(101));
    if (!wc.hIcon) {
        wc.hIcon = (HICON)LoadImage(NULL, L"service_manager.ico", IMAGE_ICON, 0, 0, LR_LOADFROMFILE | LR_DEFAULTSIZE | LR_SHARED);
    }
    
    RegisterClassW(&wc);

    // Create Window
    // Fixed size window: WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX
    hMainWnd = CreateWindowW(L"ServiceManagerClass", L"程序管理器", 
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX, 
        CW_USEDEFAULT, CW_USEDEFAULT, 800, 500, NULL, NULL, hInstance, NULL);

    if (!hMainWnd) return FALSE;

    ShowWindow(hMainWnd, nCmdShow);
    AnimateWindow(hMainWnd, 200, AW_BLEND);
    UpdateWindow(hMainWnd);

    // Message Loop
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    DeleteObject(hFont);
    return (int)msg.wParam;
}
