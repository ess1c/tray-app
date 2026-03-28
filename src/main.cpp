#include <windows.h>
#include <shellapi.h>
#include "resource.h"

static const wchar_t* CLASS_NAME = L"TrayAppMainWindow";
static const wchar_t* MUTEX_NAME = L"Local\\TrayApp_SingleInstance_Mutex";
static UINT WM_TASKBARCREATED = 0;
static NOTIFYICONDATAW nid = {};
static HWND g_hWnd = nullptr;
static bool g_showOnStart = true;

void AddTrayIcon(HWND hWnd)
{
    nid.cbSize = sizeof(nid);
    nid.hWnd = hWnd;
    nid.uID = 1;
    nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    nid.uCallbackMessage = WM_TRAYICON;
    nid.hIcon = LoadIconW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(IDI_TRAYAPP));
    wcscpy_s(nid.szTip, L"TrayApp");
    Shell_NotifyIconW(NIM_ADD, &nid);
}

void RemoveTrayIcon()
{
    Shell_NotifyIconW(NIM_DELETE, &nid);
}

void ShowMainWindow(HWND hWnd)
{
    ShowWindow(hWnd, SW_SHOW);
    SetForegroundWindow(hWnd);
}

void ExitApp(HWND hWnd)
{
    RemoveTrayIcon();
    DestroyWindow(hWnd);
}

void ShowTrayContextMenu(HWND hWnd)
{
    POINT pt;
    GetCursorPos(&pt);

    HMENU hMenu = CreatePopupMenu();
    AppendMenuW(hMenu, MF_STRING, ID_TRAY_OPEN, L"\x041E\x0442\x043A\x0440\x044B\x0442\x044C");
    AppendMenuW(hMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(hMenu, MF_STRING, ID_TRAY_EXIT, L"\x0412\x044B\x0445\x043E\x0434");

    SetForegroundWindow(hWnd);
    TrackPopupMenu(hMenu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hWnd, nullptr);
    PostMessageW(hWnd, WM_NULL, 0, 0);
    DestroyMenu(hMenu);
}

HMENU CreateMainMenu()
{
    HMENU hMenuBar = CreateMenu();
    HMENU hFileMenu = CreatePopupMenu();
    AppendMenuW(hFileMenu, MF_STRING, ID_FILE_EXIT, L"\x0412\x044B\x0445\x043E\x0434");
    AppendMenuW(hMenuBar, MF_POPUP, (UINT_PTR)hFileMenu, L"\x0424\x0430\x0439\x043B");
    return hMenuBar;
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (msg == WM_TASKBARCREATED && WM_TASKBARCREATED != 0) {
        AddTrayIcon(hWnd);
        return 0;
    }

    switch (msg) {
    case WM_CREATE:
        SetMenu(hWnd, CreateMainMenu());
        AddTrayIcon(hWnd);
        if (!g_showOnStart) {
            ShowWindow(hWnd, SW_HIDE);
        }
        return 0;

    case WM_TRAYICON:
        if (lParam == WM_LBUTTONUP) {
            ShowMainWindow(hWnd);
        } else if (lParam == WM_RBUTTONUP) {
            ShowTrayContextMenu(hWnd);
        }
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

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR lpCmdLine, int nCmdShow)
{
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
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hIcon = LoadIconW(hInstance, MAKEINTRESOURCEW(IDI_TRAYAPP));
    wc.hCursor = LoadCursorW(nullptr, (LPCWSTR)IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = CLASS_NAME;
    RegisterClassExW(&wc);

    g_hWnd = CreateWindowExW(
        0, CLASS_NAME, L"TrayApp",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 640, 480,
        nullptr, nullptr, hInstance, nullptr
    );

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
    return (int)msg.wParam;
}
