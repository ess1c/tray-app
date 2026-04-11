#include <windows.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <cstdlib>
#include "resource.h"
#include "trayapp_h.h"

#pragma comment(lib, "rpcrt4.lib")

static const wchar_t* CLASS_NAME    = L"TrayAppMainWindow";
static const wchar_t* MUTEX_NAME    = L"Local\\TrayApp_SingleInstance_Mutex";
static const wchar_t* SERVICE_NAME  = L"TrayAppService";
static const wchar_t* RPC_ENDPOINT  = L"TrayAppRpcEndpoint";

static UINT           WM_TASKBARCREATED = 0;
static NOTIFYICONDATAW nid = {};
static HWND           g_hWnd = nullptr;
static bool           g_showOnStart = true;

/* implicit binding handle used by the generated RPC client stub */
handle_t hTrayAppBinding = nullptr;

/* MIDL memory helpers */
void* __RPC_USER midl_user_allocate(size_t size) { return malloc(size); }
void  __RPC_USER midl_user_free(void* p)         { free(p); }

/* ================================================================ */
/*  Service / parent-process helpers                                 */
/* ================================================================ */

static bool IsParentService()
{
    DWORD pid = GetCurrentProcessId();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;

    /* First pass: find our parent PID */
    PROCESSENTRY32W pe = { sizeof(pe) };
    DWORD ppid = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ProcessID == pid) { ppid = pe.th32ParentProcessID; break; }
        } while (Process32NextW(snap, &pe));
    }

    if (ppid == 0) { CloseHandle(snap); return false; }

    /* Second pass: find parent's exe name from the same snapshot */
    pe.dwSize = sizeof(pe);
    bool found = false;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ProcessID == ppid) {
                found = (_wcsicmp(pe.szExeFile, L"TrayService.exe") == 0);
                break;
            }
        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);
    return found;
}

static bool TryStartService()
{
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hSCM) return false;

    SC_HANDLE hSvc = OpenServiceW(hSCM, SERVICE_NAME,
                                  SERVICE_START | SERVICE_QUERY_STATUS);
    if (!hSvc) { CloseServiceHandle(hSCM); return false; }

    SERVICE_STATUS_PROCESS ssp = {};
    DWORD needed = 0;
    QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO,
                         reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &needed);

    if (ssp.dwCurrentState == SERVICE_STOPPED) {
        StartServiceW(hSvc, 0, nullptr);
        for (int i = 0; i < 30; i++) {
            Sleep(1000);
            QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO,
                                 reinterpret_cast<LPBYTE>(&ssp),
                                 sizeof(ssp), &needed);
            if (ssp.dwCurrentState == SERVICE_RUNNING) break;
        }
    }

    bool ok = (ssp.dwCurrentState == SERVICE_RUNNING);
    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);
    return ok;
}

static bool IsServiceRunning()
{
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hSCM) return false;

    SC_HANDLE hSvc = OpenServiceW(hSCM, SERVICE_NAME, SERVICE_QUERY_STATUS);
    if (!hSvc) { CloseServiceHandle(hSCM); return false; }

    SERVICE_STATUS_PROCESS ssp = {};
    DWORD needed = 0;
    QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO,
                         reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &needed);

    bool running = (ssp.dwCurrentState == SERVICE_RUNNING);
    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);
    return running;
}

/* ================================================================ */
/*  RPC client — call the service to stop itself                     */
/* ================================================================ */

static void CallRpcStopService()
{
    RPC_WSTR binding = nullptr;
    RpcStringBindingComposeW(
        nullptr,
        reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(L"ncalrpc")),
        nullptr,
        reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(RPC_ENDPOINT)),
        nullptr, &binding);

    RpcBindingFromStringBindingW(binding, &hTrayAppBinding);
    RpcStringFreeW(&binding);

    RpcTryExcept {
        ::RpcStopService();
    } RpcExcept(1) {
    } RpcEndExcept;

    RpcBindingFree(&hTrayAppBinding);
}

/* ================================================================ */
/*  Tray icon / window helpers                                       */
/* ================================================================ */

static void AddTrayIcon(HWND hWnd)
{
    nid.cbSize           = sizeof(nid);
    nid.hWnd             = hWnd;
    nid.uID              = 1;
    nid.uFlags           = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    nid.uCallbackMessage = WM_TRAYICON;
    nid.hIcon            = LoadIconW(GetModuleHandleW(nullptr),
                                     MAKEINTRESOURCEW(IDI_TRAYAPP));
    wcscpy_s(nid.szTip, L"TrayApp");
    Shell_NotifyIconW(NIM_ADD, &nid);
}

static void RemoveTrayIcon()
{
    Shell_NotifyIconW(NIM_DELETE, &nid);
}

static void ShowMainWindow(HWND hWnd)
{
    ShowWindow(hWnd, SW_SHOW);
    SetForegroundWindow(hWnd);
}

static void ExitApp(HWND hWnd)
{
    RemoveTrayIcon();
    DestroyWindow(hWnd);
    CallRpcStopService();
}

static void ShowTrayContextMenu(HWND hWnd)
{
    POINT pt;
    GetCursorPos(&pt);

    HMENU hMenu = CreatePopupMenu();
    AppendMenuW(hMenu, MF_STRING, ID_TRAY_OPEN,
                L"\x041E\x0442\x043A\x0440\x044B\x0442\x044C");       // Открыть
    AppendMenuW(hMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(hMenu, MF_STRING, ID_TRAY_EXIT,
                L"\x0412\x044B\x0445\x043E\x0434");                    // Выход

    SetForegroundWindow(hWnd);
    TrackPopupMenu(hMenu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hWnd, nullptr);
    PostMessageW(hWnd, WM_NULL, 0, 0);
    DestroyMenu(hMenu);
}

static HMENU CreateMainMenu()
{
    HMENU hMenuBar  = CreateMenu();
    HMENU hFileMenu = CreatePopupMenu();
    AppendMenuW(hFileMenu, MF_STRING, ID_FILE_EXIT,
                L"\x0412\x044B\x0445\x043E\x0434");                    // Выход
    AppendMenuW(hMenuBar, MF_POPUP, reinterpret_cast<UINT_PTR>(hFileMenu),
                L"\x0424\x0430\x0439\x043B");                          // Файл
    return hMenuBar;
}

/* ================================================================ */
/*  Window procedure                                                 */
/* ================================================================ */

static LRESULT CALLBACK WndProc(HWND hWnd, UINT msg,
                                WPARAM wParam, LPARAM lParam)
{
    if (msg == WM_TASKBARCREATED && WM_TASKBARCREATED != 0) {
        AddTrayIcon(hWnd);
        return 0;
    }

    switch (msg)
    {
    case WM_CREATE:
        SetMenu(hWnd, CreateMainMenu());
        AddTrayIcon(hWnd);
        if (!g_showOnStart)
            ShowWindow(hWnd, SW_HIDE);
        return 0;

    case WM_TRAYICON:
        if (lParam == WM_LBUTTONUP)
            ShowMainWindow(hWnd);
        else if (lParam == WM_RBUTTONUP)
            ShowTrayContextMenu(hWnd);
        return 0;

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case ID_FILE_EXIT:
        case ID_TRAY_EXIT:
            ExitApp(hWnd);
            return 0;
        case ID_TRAY_OPEN:
            ShowMainWindow(hWnd);
            return 0;
        }
        break;

    case WM_CLOSE:
        ShowWindow(hWnd, SW_HIDE);
        return 0;

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

/* ================================================================ */
/*  wWinMain                                                         */
/* ================================================================ */

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR lpCmdLine, int nCmdShow)
{
    /* --- Requirement 1: if service is stopped, start it and exit --- */
    if (!IsServiceRunning()) {
        TryStartService();
        return 0;
    }

    /* --- Requirement 2: exit if parent is not the service --- */
    if (!IsParentService()) {
        return 0;
    }

    /* --- Single-instance mutex (from practice 1) --- */
    HANDLE hMutex = CreateMutexW(nullptr, TRUE, MUTEX_NAME);
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        if (hMutex) CloseHandle(hMutex);
        return 0;
    }

    if (lpCmdLine && wcsstr(lpCmdLine, L"--hidden")) {
        g_showOnStart = false;
    }

    WM_TASKBARCREATED = RegisterWindowMessageW(L"TaskbarCreated");

    WNDCLASSEXW wc = {};
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = WndProc;
    wc.hInstance      = hInstance;
    wc.hIcon          = LoadIconW(hInstance, MAKEINTRESOURCEW(IDI_TRAYAPP));
    wc.hCursor        = LoadCursorW(nullptr, reinterpret_cast<LPCWSTR>(IDC_ARROW));
    wc.hbrBackground  = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    wc.lpszClassName  = CLASS_NAME;
    RegisterClassExW(&wc);

    g_hWnd = CreateWindowExW(
        0, CLASS_NAME, L"TrayApp",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 640, 480,
        nullptr, nullptr, hInstance, nullptr);

    if (!g_hWnd) {
        CloseHandle(hMutex);
        return 1;
    }

    if (g_showOnStart) {
        ShowWindow(g_hWnd, nCmdShow);
        UpdateWindow(g_hWnd);
    }

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    CloseHandle(hMutex);
    return static_cast<int>(msg.wParam);
}
