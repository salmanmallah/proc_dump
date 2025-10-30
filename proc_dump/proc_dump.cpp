// proc_dump.cpp

// Compile with Visual Studio (x64). Link with DbgHelp.lib, Crypt32.lib

// Run as Administrator.

// Usage: proc_dump <pid|process_name> <output_dir>



#include <windows.h>

#include <tlhelp32.h>

#include <tchar.h>

#include <stdio.h>

#include <string>

#include <vector>

#include <fstream>

#include <DbgHelp.h>

#include <wincrypt.h>

#pragma comment(lib, "Dbghelp.lib")

#pragma comment(lib, "Crypt32.lib")



using namespace std;



static string WStringToUtf8(const wstring& s) {

    if (s.empty()) return string();

    int size_needed = WideCharToMultiByte(CP_UTF8, 0, s.c_str(), -1, NULL, 0, NULL, NULL);

    if (size_needed <= 0) return string();

    string result(size_needed - 1, '\0');

    WideCharToMultiByte(CP_UTF8, 0, s.c_str(), -1, &result[0], size_needed, NULL, NULL);

    return result;

}



static wstring Utf8ToWString(const string& s) {

    if (s.empty()) return wstring();

    int size_needed = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, NULL, 0);

    if (size_needed <= 0) return wstring();

    wstring result(size_needed - 1, L'\0');

    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &result[0], size_needed);

    return result;

}



// Minimal path helpers to avoid relying on std::filesystem

static bool PathExists(const wstring& p) {

    DWORD attr = GetFileAttributesW(p.c_str());

    return (attr != INVALID_FILE_ATTRIBUTES);

}



static bool CreateDirectories(const wstring& path) {

    if (path.empty()) return false;

    // If already exists and is a directory, done

    if (PathExists(path)) return true;



    // Build each component and create

    wstring accum;

    // Handle drive letter or UNC prefix

    size_t i = 0;

    if (path.size() >= 2 && path[1] == L':') {

        accum.append(path.substr(0, 2)); // "C:"

        i = 2;

    }
    else if (path.size() >= 2 && path[0] == L'\\' && path[1] == L'\\') {

        // UNC path: keep leading \\server\share

        accum = L"\\\\";

        i = 2;

    }



    for (; i < path.size(); ++i) {

        wchar_t c = path[i];

        accum.push_back(c);

        if (c == L'\\' || c == L'/') {

            // try create

            CreateDirectoryW(accum.c_str(), NULL);

        }

    }

    // finally create full path

    if (!PathExists(path)) {

        if (!CreateDirectoryW(path.c_str(), NULL)) {

            DWORD err = GetLastError();

            // if already exists, consider success

            if (err != ERROR_ALREADY_EXISTS) return false;

        }

    }

    return true;

}



static wstring PathJoin(const wstring& dir, const wstring& file) {

    if (file.empty()) return dir;

    if (file.size() >= 2 && (file[1] == L':' || (file[0] == L'\\' && file[1] == L'\\'))) {

        // file is absolute

        return file;

    }

    if (dir.empty()) return file;

    wstring d = dir;

    if (d.back() != L'\\' && d.back() != L'/') d.push_back(L'\\');

    return d + file;

}



static wstring PathStem(const wstring& path) {

    // get filename

    size_t pos = path.find_last_of(L"\\/");

    wstring name = (pos == wstring::npos) ? path : path.substr(pos + 1);

    size_t dot = name.find_last_of(L'.');

    if (dot == wstring::npos) return name;

    return name.substr(0, dot);

}



DWORD FindPidByName(const wstring& name) {

    PROCESSENTRY32W pe{ sizeof(pe) };

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snap == INVALID_HANDLE_VALUE) return 0;

    if (Process32FirstW(snap, &pe)) {

        do {

            if (_wcsicmp(pe.szExeFile, name.c_str()) == 0) {

                CloseHandle(snap);

                return pe.th32ProcessID;

            }

        } while (Process32NextW(snap, &pe));

    }

    CloseHandle(snap);

    return 0;

}



bool DumpProcess(DWORD pid, const wstring& outFile) {

    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_CREATE_THREAD | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid);

    if (!hProc) return false;



    HANDLE hFile = CreateFileW(outFile.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE) { CloseHandle(hProc); return false; }



    BOOL ok = MiniDumpWriteDump(hProc, pid, hFile, MiniDumpWithFullMemory, NULL, NULL, NULL);



    CloseHandle(hFile);

    CloseHandle(hProc);

    return ok == TRUE;

}



string SHA256_File(const wstring& path) {

    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE) return string();



    HCRYPTPROV hProv = 0;

    HCRYPTHASH hHash = 0;

    BYTE buffer[8192];

    DWORD read = 0;

    BYTE hash[32];

    DWORD cbHash = sizeof(hash);



    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) { CloseHandle(hFile); return string(); }

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) { CryptReleaseContext(hProv, 0); CloseHandle(hFile); return string(); }



    while (ReadFile(hFile, buffer, sizeof(buffer), &read, NULL) && read) {

        CryptHashData(hHash, buffer, read, 0);

    }

    if (!CryptGetHashParam(hHash, HP_HASHVAL, hash, &cbHash, 0)) { CryptDestroyHash(hHash); CryptReleaseContext(hProv, 0); CloseHandle(hFile); return string(); }



    // hex

    char hex[65]; hex[64] = 0;

    for (DWORD i = 0; i < cbHash; i++) sprintf_s(hex + i * 2, 3, "%02x", hash[i]);



    CryptDestroyHash(hHash);

    CryptReleaseContext(hProv, 0);

    CloseHandle(hFile);

    return string(hex);

}



int wmain(int argc, wchar_t* argv[]) {

    if (argc < 3) {

        wprintf(L"Usage: %ls <pid|process_name.exe> <output_dir>\n", argv[0]);

        return 1;

    }

    wstring target = argv[1];

    wstring outdir = argv[2];



    if (!PathExists(outdir)) CreateDirectories(outdir);



    DWORD pid = 0;

    // if numeric: parse wide string directly

    wchar_t* endptr = nullptr;

    unsigned long val = wcstoul(target.c_str(), &endptr, 0);

    if (endptr != nullptr && *endptr == L'\0' && val != 0) {

        pid = static_cast<DWORD>(val);

    }
    else {

        // not a pure number: treat as process name

        pid = FindPidByName(target);

    }



    if (pid == 0) {

        // try again treating as name (in case of path or different casing)

        pid = FindPidByName(target);

    }

    if (pid == 0) {

        wprintf(L"Could not find process: %ls\n", target.c_str());

        return 2;

    }



    wchar_t procName[MAX_PATH];

    swprintf_s(procName, MAX_PATH, L"%s_%u.dmp", L"proc", pid);

    wstring outPath = PathJoin(outdir, procName);



    wprintf(L"Dumping PID %u -> %ls\n", pid, outPath.c_str());

    if (!DumpProcess(pid, outPath)) {

        wprintf(L"MiniDumpWriteDump failed. Try running as Administrator and ensure SeDebugPrivilege present.\n");

        return 3;

    }



    wprintf(L"Dump complete. Calculating SHA256...\n");

    string sha = SHA256_File(outPath);

    if (sha.empty()) {

        wprintf(L"Hash failed.\n");

    }
    else {

        wstring sha_w = Utf8ToWString(sha);

        wprintf(L"SHA256: %ls\n", sha_w.c_str());

        // write metadata

        wstring stem = PathStem(outPath);

        wstring metaPath = PathJoin(outdir, stem + L".json");

        string metaPathUtf8 = WStringToUtf8(metaPath);

        ofstream meta(metaPathUtf8, ios::binary);

        if (meta) {

            SYSTEMTIME st; GetSystemTime(&st);

            wchar_t timebuf[128];

            swprintf_s(timebuf, 128, L"%04d-%02d-%02dT%02d:%02d:%02dZ", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

            meta << "{\n";

            meta << " \"dump_file\": \"" << WStringToUtf8(outPath) << "\",\n";

            meta << " \"sha256\": \"" << sha << "\",\n";

            meta << " \"pid\": " << pid << ",\n";

            meta << " \"timestamp_utc\": \"" << WStringToUtf8(wstring(timebuf)) << "\"\n";

            meta << "}\n";

            meta.close();

            wprintf(L"Metadata written to %ls\n", metaPath.c_str());

        }
        else {

            wprintf(L"Failed to write metadata to %ls\n", metaPath.c_str());

        }

    }



    return 0;

}