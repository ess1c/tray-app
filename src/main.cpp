#include <windows.h>
#include <shellapi.h>
#include <shlobj.h>
#include <commdlg.h>
#include <tlhelp32.h>
#include <commctrl.h>
#include <wincred.h>
#include <cstdlib>
#include <string>
#include "resource.h"
#include "trayapp_h.h"
#include "../service/process_protect.h"

#pragma comment(lib, "rpcrt4.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "credui.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "shell32.lib")

/* ================================================================ */
/*  Globals                                                          */
/* ================================================================ */

static const wchar_t* CLASS_NAME    = L"TrayAppMainWindow";
static const wchar_t* MUTEX_NAME    = L"Local\\TrayApp_SingleInstance_Mutex";
static const wchar_t* SERVICE_NAME  = L"TrayAppService";
static const wchar_t* RPC_ENDPOINT  = L"TrayAppRpcEndpoint";

static UINT            WM_TASKBARCREATED = 0;
static NOTIFYICONDATAW nid = {};
static HWND            g_hWnd = nullptr;
static bool            g_showOnStart = true;
static UINT_PTR        g_pollTimer = 0;

enum class View { Login, Activation, Status };
static View         g_view = View::Login;

static std::wstring g_username;
static std::wstring g_licenseExpiry;
static bool         g_authenticated = false;
static bool         g_hasLicense    = false;

/* Login form controls */
static HWND hLblUser = nullptr, hEditUser = nullptr;
static HWND hLblPass = nullptr, hEditPass = nullptr;
static HWND hBtnLogin = nullptr, hLblLoginErr = nullptr;

/* Activation form controls */
static HWND hLblActPrompt = nullptr, hEditActCode = nullptr;
static HWND hBtnActivate = nullptr, hLblActErr = nullptr;

/* Status view controls */
static HWND hLblWelcome = nullptr, hLblLicense = nullptr, hLblAvStatus = nullptr, hLblAvDb = nullptr;

/* RPC */
handle_t hTrayAppBinding = nullptr;
void* __RPC_USER midl_user_allocate(size_t size) { return malloc(size); }
void  __RPC_USER midl_user_free(void* p)         { free(p); }

/* ================================================================ */
/*  Подтверждение остановки на Secure Desktop                        */
/* ================================================================ */

/* Показывает стандартный системный диалог запроса учётных данных
   на Secure Desktop (CREDUIWIN_SECURE_PROMPT). Используется как
   подтверждение опасных операций — Secure Desktop защищён от
   перехвата другими процессами. */
static bool ConfirmStopOnSecureDesktop(HWND owner)
{
    CREDUI_INFOW info = { sizeof(info) };
    info.hwndParent     = owner;
    info.pszCaptionText = L"\x041F\x043E\x0434\x0442\x0432\x0435\x0440\x0436\x0434\x0435\x043D\x0438\x0435"; // Подтверждение
    info.pszMessageText = L"\x041E\x0441\x0442\x0430\x043D\x043E\x0432\x0438\x0442\x044C \x0441\x043B\x0443\x0436\x0431\x0443 TrayApp?\n"
                          L"\x0412\x0432\x0435\x0434\x0438\x0442\x0435 \x0443\x0447\x0451\x0442\x043D\x044B\x0435 \x0434\x0430\x043D\x043D\x044B\x0435 \x0434\x043B\x044F \x043F\x043E\x0434\x0442\x0432\x0435\x0440\x0436\x0434\x0435\x043D\x0438\x044F."; // Остановить службу TrayApp? Введите учётные данные для подтверждения.

    ULONG  authPackage   = 0;
    LPVOID outAuthBuffer = nullptr;
    ULONG  outAuthSize   = 0;
    BOOL   savePass      = FALSE;

    DWORD r = CredUIPromptForWindowsCredentialsW(
        &info, 0, &authPackage,
        nullptr, 0,
        &outAuthBuffer, &outAuthSize, &savePass,
        CREDUIWIN_GENERIC | CREDUIWIN_SECURE_PROMPT);

    if (outAuthBuffer) {
        SecureZeroMemory(outAuthBuffer, outAuthSize);
        CoTaskMemFree(outAuthBuffer);
    }
    return r == ERROR_SUCCESS;
}

/* ================================================================ */
/*  Service / parent helpers                                         */
/* ================================================================ */

static bool IsParentService()
{
    DWORD pid = GetCurrentProcessId();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W pe = { sizeof(pe) };
    DWORD ppid = 0;
    if (Process32FirstW(snap, &pe)) {
        do { if (pe.th32ProcessID == pid) { ppid = pe.th32ParentProcessID; break; } }
        while (Process32NextW(snap, &pe));
    }
    if (ppid == 0) { CloseHandle(snap); return false; }

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

    SERVICE_STATUS_PROCESS ssp = {}; DWORD needed = 0;
    QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO,
                         (LPBYTE)&ssp, sizeof(ssp), &needed);
    if (ssp.dwCurrentState == SERVICE_STOPPED) {
        StartServiceW(hSvc, 0, nullptr);
        for (int i = 0; i < 30; i++) {
            Sleep(1000);
            QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO,
                                 (LPBYTE)&ssp, sizeof(ssp), &needed);
            if (ssp.dwCurrentState == SERVICE_RUNNING) break;
        }
    }
    bool ok = (ssp.dwCurrentState == SERVICE_RUNNING);
    CloseServiceHandle(hSvc); CloseServiceHandle(hSCM);
    return ok;
}

static bool IsServiceRunning()
{
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hSCM) return false;
    SC_HANDLE hSvc = OpenServiceW(hSCM, SERVICE_NAME, SERVICE_QUERY_STATUS);
    if (!hSvc) { CloseServiceHandle(hSCM); return false; }
    SERVICE_STATUS_PROCESS ssp = {}; DWORD needed = 0;
    QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO,
                         (LPBYTE)&ssp, sizeof(ssp), &needed);
    bool running = (ssp.dwCurrentState == SERVICE_RUNNING);
    CloseServiceHandle(hSvc); CloseServiceHandle(hSCM);
    return running;
}

/* ================================================================ */
/*  RPC client wrappers                                              */
/* ================================================================ */

static bool BindRpc()
{
    if (hTrayAppBinding) return true;
    RPC_WSTR binding = nullptr;
    RpcStringBindingComposeW(nullptr,
        (RPC_WSTR)L"ncalrpc", nullptr,
        (RPC_WSTR)RPC_ENDPOINT, nullptr, &binding);
    RPC_STATUS s = RpcBindingFromStringBindingW(binding, &hTrayAppBinding);
    RpcStringFreeW(&binding);
    return s == RPC_S_OK;
}

static void UnbindRpc()
{
    if (hTrayAppBinding) { RpcBindingFree(&hTrayAppBinding); hTrayAppBinding = nullptr; }
}

static void CallRpcStopService()
{
    if (!BindRpc()) return;
    RpcTryExcept { ::RpcStopService(); }
    RpcExcept(1) {} RpcEndExcept;
}

static long CallRpcGetCurrentUser(bool& outAuthed, std::wstring& outName)
{
    outAuthed = false; outName.clear();
    if (!BindRpc()) return 3;
    long rc = 3, isAuth = 0; wchar_t* uname = nullptr;
    RpcTryExcept { rc = ::RpcGetCurrentUser(&isAuth, &uname); }
    RpcExcept(1) { rc = 3; } RpcEndExcept;
    outAuthed = (isAuth != 0);
    if (uname) { outName = uname; midl_user_free(uname); }
    return rc;
}

static long CallRpcLogin(const std::wstring& u, const std::wstring& p,
                         std::wstring& outErr)
{
    outErr.clear();
    if (!BindRpc()) { outErr = L"RPC not available"; return 3; }
    long rc = 3; wchar_t* err = nullptr;
    RpcTryExcept { rc = ::RpcLogin(u.c_str(), p.c_str(), &err); }
    RpcExcept(1) { rc = 3; } RpcEndExcept;
    if (err) { outErr = err; midl_user_free(err); }
    return rc;
}

static void CallRpcLogout()
{
    if (!BindRpc()) return;
    RpcTryExcept { ::RpcLogout(); }
    RpcExcept(1) {} RpcEndExcept;
}

static long CallRpcGetLicense(bool& outHas, std::wstring& outExpiry,
                              std::wstring& outErr)
{
    outHas = false; outExpiry.clear(); outErr.clear();
    if (!BindRpc()) { outErr = L"RPC not available"; return 3; }
    long rc = 3, has = 0; wchar_t* exp = nullptr; wchar_t* err = nullptr;
    RpcTryExcept { rc = ::RpcGetLicenseStatus(&has, &exp, &err); }
    RpcExcept(1) { rc = 3; } RpcEndExcept;
    outHas = (has != 0);
    if (exp) { outExpiry = exp; midl_user_free(exp); }
    if (err) { outErr    = err; midl_user_free(err); }
    return rc;
}

static long CallRpcActivate(const std::wstring& code, std::wstring& outErr)
{
    outErr.clear();
    if (!BindRpc()) { outErr = L"RPC not available"; return 3; }
    long rc = 3; wchar_t* err = nullptr;
    RpcTryExcept { rc = ::RpcActivate(code.c_str(), &err); }
    RpcExcept(1) { rc = 3; } RpcEndExcept;
    if (err) { outErr = err; midl_user_free(err); }
    return rc;
}

/* ── Антивирусные RPC-вызовы ───────────────────────────────────── */

static long CallRpcGetAvInfo(bool& outLoaded, long& outCount, std::wstring& outDate)
{
    outLoaded = false; outCount = 0; outDate.clear();
    if (!BindRpc()) return 3;
    long rc = 3, loaded = 0, count = 0; wchar_t* date = nullptr;
    RpcTryExcept { rc = ::RpcGetAntivirusInfo(&loaded, &count, &date); }
    RpcExcept(1) { rc = 3; UnbindRpc(); } RpcEndExcept;
    outLoaded = (loaded != 0);
    outCount  = count;
    if (date) { outDate = date; midl_user_free(date); }
    return rc;
}

static long CallRpcScanFile(const std::wstring& path, std::wstring& outResult)
{
    outResult.clear();
    if (!BindRpc()) return 3;
    long rc = 3; wchar_t* res = nullptr;
    RpcTryExcept { rc = ::RpcScanFile(path.c_str(), &res); }
    RpcExcept(1) { rc = 3; UnbindRpc(); } RpcEndExcept;
    if (res) { outResult = res; midl_user_free(res); }
    return rc;
}

static long CallRpcScanDirectory(const std::wstring& path, std::wstring& outResult)
{
    outResult.clear();
    if (!BindRpc()) return 3;
    long rc = 3; wchar_t* res = nullptr;
    RpcTryExcept { rc = ::RpcScanDirectory(path.c_str(), &res); }
    RpcExcept(1) { rc = 3; UnbindRpc(); } RpcEndExcept;
    if (res) { outResult = res; midl_user_free(res); }
    return rc;
}

static long CallRpcScanAllDrives(std::wstring& outResult)
{
    outResult.clear();
    if (!BindRpc()) return 3;
    long rc = 3; wchar_t* res = nullptr;
    RpcTryExcept { rc = ::RpcScanAllDrives(&res); }
    RpcExcept(1) { rc = 3; UnbindRpc(); } RpcEndExcept;
    if (res) { outResult = res; midl_user_free(res); }
    return rc;
}

/* ================================================================ */
/*  Tray + menu                                                      */
/* ================================================================ */

static void AddTrayIcon(HWND hWnd)
{
    nid.cbSize = sizeof(nid);
    nid.hWnd = hWnd; nid.uID = 1;
    nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    nid.uCallbackMessage = WM_TRAYICON;
    nid.hIcon = LoadIconW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(IDI_TRAYAPP));
    wcscpy_s(nid.szTip, L"TrayApp");
    Shell_NotifyIconW(NIM_ADD, &nid);
}

static void RemoveTrayIcon() { Shell_NotifyIconW(NIM_DELETE, &nid); }

static void ShowMainWindow(HWND hWnd) { ShowWindow(hWnd, SW_SHOW); SetForegroundWindow(hWnd); }

static void ExitApp(HWND hWnd)
{
    /* Доп: подтверждение остановки на Secure Desktop */
    if (!ConfirmStopOnSecureDesktop(hWnd)) {
        return; // отмена — служба продолжает работу
    }
    RemoveTrayIcon();
    DestroyWindow(hWnd);
    CallRpcStopService();
}

static void ShowTrayContextMenu(HWND hWnd)
{
    POINT pt; GetCursorPos(&pt);
    HMENU hMenu = CreatePopupMenu();
    AppendMenuW(hMenu, MF_STRING, ID_TRAY_OPEN,
                L"\x041E\x0442\x043A\x0440\x044B\x0442\x044C");          // Открыть
    AppendMenuW(hMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(hMenu, MF_STRING, ID_TRAY_EXIT,
                L"\x0412\x044B\x0445\x043E\x0434");                       // Выход
    SetForegroundWindow(hWnd);
    TrackPopupMenu(hMenu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hWnd, nullptr);
    PostMessageW(hWnd, WM_NULL, 0, 0);
    DestroyMenu(hMenu);
}

static HMENU CreateMainMenu()
{
    HMENU bar = CreateMenu();

    HMENU file = CreatePopupMenu();
    AppendMenuW(file, MF_STRING, ID_FILE_LOGOUT,
                L"\x0412\x044B\x0439\x0442\x0438 \x0438\x0437 \x0430\x043A\x043A\x0430\x0443\x043D\x0442\x0430"); // Выйти из аккаунта
    AppendMenuW(file, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(file, MF_STRING, ID_FILE_EXIT,
                L"\x0412\x044B\x0445\x043E\x0434");                       // Выход
    AppendMenuW(bar, MF_POPUP, (UINT_PTR)file,
                L"\x0424\x0430\x0439\x043B");                              // Файл

    /* Меню "Антивирус" */
    HMENU av = CreatePopupMenu();
    AppendMenuW(av, MF_STRING, ID_AV_SCAN_FILE,
                L"\x0421\x043A\x0430\x043D\x0438\x0440\x043E\x0432\x0430\x0442\x044C \x0444\x0430\x0439\x043B..."); // Сканировать файл...
    AppendMenuW(av, MF_STRING, ID_AV_SCAN_DIR,
                L"\x0421\x043A\x0430\x043D\x0438\x0440\x043E\x0432\x0430\x0442\x044C \x043F\x0430\x043F\x043A\x0443..."); // Сканировать папку...
    AppendMenuW(av, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(av, MF_STRING, ID_AV_SCAN_ALL,
                L"\x0421\x043A\x0430\x043D\x0438\x0440\x043E\x0432\x0430\x0442\x044C \x0432\x0441\x0435 \x0434\x0438\x0441\x043A\x0438"); // Сканировать все диски
    AppendMenuW(bar, MF_POPUP, (UINT_PTR)av,
                L"\x0410\x043D\x0442\x0438\x0432\x0438\x0440\x0443\x0441");  // Антивирус

    return bar;
}

/* ================================================================ */
/*  View management — login / activation / status                    */
/* ================================================================ */

static void ShowLoginControls(int show)
{
    int s = show ? SW_SHOW : SW_HIDE;
    ShowWindow(hLblUser,    s); ShowWindow(hEditUser,    s);
    ShowWindow(hLblPass,    s); ShowWindow(hEditPass,    s);
    ShowWindow(hBtnLogin,   s); ShowWindow(hLblLoginErr, s);
}
static void ShowActControls(int show)
{
    int s = show ? SW_SHOW : SW_HIDE;
    ShowWindow(hLblActPrompt, s); ShowWindow(hEditActCode, s);
    ShowWindow(hBtnActivate,  s); ShowWindow(hLblActErr,   s);
}
static void ShowStatusControls(int show)
{
    int s = show ? SW_SHOW : SW_HIDE;
    ShowWindow(hLblWelcome,  s); ShowWindow(hLblLicense,  s);
    ShowWindow(hLblAvStatus, s); ShowWindow(hLblAvDb, s);
}

static void SetView(View v)
{
    g_view = v;
    ShowLoginControls (v == View::Login      ? 1 : 0);
    ShowActControls   (v == View::Activation ? 1 : 0);
    ShowStatusControls(v == View::Status     ? 1 : 0);

    if (v == View::Status) {
        std::wstring u = L"\x041F\x043E\x043B\x044C\x0437\x043E\x0432\x0430\x0442\x0435\x043B\x044C: " + g_username; // Пользователь:
        SetWindowTextW(hLblWelcome, u.c_str());

        std::wstring l;
        if (g_hasLicense) {
            l = L"\x041B\x0438\x0446\x0435\x043D\x0437\x0438\x044F \x0434\x043E: " + g_licenseExpiry; // Лицензия до:
            SetWindowTextW(hLblLicense,  l.c_str());
            SetWindowTextW(hLblAvStatus,
                L"\x0410\x043D\x0442\x0438\x0432\x0438\x0440\x0443\x0441: \x0410\x043A\x0442\x0438\x0432\x0435\x043D"); // Антивирус: Активен

            /* Информация об антивирусных базах (требование 1 GUI практики 5) */
            bool loaded = false; long count = 0; std::wstring date;
            CallRpcGetAvInfo(loaded, count, date);
            std::wstring dbInfo;
            if (loaded) {
                dbInfo = L"\x0411\x0430\x0437\x044B: " + date +                 // Базы:
                         L"  |  " +
                         L"\x0437\x0430\x043F\x0438\x0441\x0435\x0439: " +      // записей:
                         std::to_wstring(count);
            } else {
                dbInfo = L"\x0411\x0430\x0437\x044B \x043D\x0435 \x0437\x0430\x0433\x0440\x0443\x0436\x0435\x043D\x044B"; // Базы не загружены
            }
            SetWindowTextW(hLblAvDb, dbInfo.c_str());
        } else {
            SetWindowTextW(hLblLicense,
                L"\x041B\x0438\x0446\x0435\x043D\x0437\x0438\x044F \x043E\x0442\x0441\x0443\x0442\x0441\x0442\x0432\x0443\x0435\x0442"); // Лицензия отсутствует
            SetWindowTextW(hLblAvStatus,
                L"\x0410\x043D\x0442\x0438\x0432\x0438\x0440\x0443\x0441: \x0417\x0430\x0431\x043B\x043E\x043A\x0438\x0440\x043E\x0432\x0430\x043D"); // Антивирус: Заблокирован
            SetWindowTextW(hLblAvDb, L"");
        }
    }
}

/* Recompute current view based on RPC state */
static void RefreshView()
{
    bool authed = false; std::wstring uname;
    CallRpcGetCurrentUser(authed, uname);
    g_authenticated = authed;
    g_username = uname;

    if (!authed) {
        g_hasLicense = false; g_licenseExpiry.clear();
        SetView(View::Login);
        return;
    }

    bool hasLic = false; std::wstring exp, err;
    CallRpcGetLicense(hasLic, exp, err);
    g_hasLicense    = hasLic;
    g_licenseExpiry = exp;

    if (!hasLic) { SetView(View::Activation); return; }
    SetView(View::Status);
}

/* ================================================================ */
/*  Window controls — created once, hidden/shown per view            */
/* ================================================================ */

static HWND MkLabel (HWND parent, LPCWSTR text, int x, int y, int w, int h, int id = 0)
{
    return CreateWindowExW(0, L"STATIC", text, WS_CHILD,
        x, y, w, h, parent, (HMENU)(INT_PTR)id, nullptr, nullptr);
}
static HWND MkEdit  (HWND parent, int x, int y, int w, int h, int id, DWORD extra = 0)
{
    return CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_TABSTOP | extra,
        x, y, w, h, parent, (HMENU)(INT_PTR)id, nullptr, nullptr);
}
static HWND MkButton(HWND parent, LPCWSTR text, int x, int y, int w, int h, int id)
{
    return CreateWindowExW(0, L"BUTTON", text, WS_CHILD | WS_TABSTOP | BS_DEFPUSHBUTTON,
        x, y, w, h, parent, (HMENU)(INT_PTR)id, nullptr, nullptr);
}

static void CreateAllControls(HWND hWnd)
{
    HFONT hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);

    /* Login */
    hLblUser     = MkLabel (hWnd, L"\x041B\x043E\x0433\x0438\x043D:",                        40,  40, 100, 20); // Логин:
    hEditUser    = MkEdit  (hWnd,                                                            150,  38, 280, 24, IDC_LOGIN_USER);
    hLblPass     = MkLabel (hWnd, L"\x041F\x0430\x0440\x043E\x043B\x044C:",                  40,  80, 100, 20); // Пароль:
    hEditPass    = MkEdit  (hWnd,                                                            150,  78, 280, 24, IDC_LOGIN_PASS, ES_PASSWORD);
    hBtnLogin    = MkButton(hWnd, L"\x0412\x043E\x0439\x0442\x0438",                         150, 120, 120,  30, IDC_LOGIN_OK); // Войти
    hLblLoginErr = MkLabel (hWnd, L"",                                                        40, 170, 500,  40, IDC_LOGIN_ERROR);

    /* Activation */
    hLblActPrompt = MkLabel (hWnd, L"\x041A\x043E\x0434 \x0430\x043A\x0442\x0438\x0432\x0430\x0446\x0438\x0438:", 40, 40, 200, 20); // Код активации:
    hEditActCode  = MkEdit  (hWnd,                                                                                 40, 70, 390, 24, IDC_ACT_CODE);
    hBtnActivate  = MkButton(hWnd, L"\x0410\x043A\x0442\x0438\x0432\x0438\x0440\x043E\x0432\x0430\x0442\x044C",   40, 110, 160, 30, IDC_ACT_OK); // Активировать
    hLblActErr    = MkLabel (hWnd, L"",                                                                            40, 160, 500, 60, IDC_ACT_ERROR);

    /* Status */
    hLblWelcome  = MkLabel(hWnd, L"", 40,  40, 540, 24, IDC_STATUS_USER);
    hLblLicense  = MkLabel(hWnd, L"", 40,  80, 540, 24, IDC_STATUS_LIC);
    hLblAvStatus = MkLabel(hWnd, L"", 40, 120, 540, 24, IDC_STATUS_AV);
    hLblAvDb     = MkLabel(hWnd, L"", 40, 160, 540, 24, IDC_STATUS_AVDB);

    /* Apply font to all */
    HWND all[] = {
        hLblUser, hEditUser, hLblPass, hEditPass, hBtnLogin, hLblLoginErr,
        hLblActPrompt, hEditActCode, hBtnActivate, hLblActErr,
        hLblWelcome, hLblLicense, hLblAvStatus, hLblAvDb
    };
    for (HWND h : all) SendMessageW(h, WM_SETFONT, (WPARAM)hFont, TRUE);
}

/* ================================================================ */
/*  Event handlers                                                   */
/* ================================================================ */

static void OnLoginClick(HWND hWnd)
{
    wchar_t u[128] = {}, p[128] = {};
    GetWindowTextW(hEditUser, u, _countof(u));
    GetWindowTextW(hEditPass, p, _countof(p));

    if (!*u || !*p) {
        SetWindowTextW(hLblLoginErr,
            L"\x0417\x0430\x043F\x043E\x043B\x043D\x0438\x0442\x0435 \x0432\x0441\x0435 \x043F\x043E\x043B\x044F"); // Заполните все поля
        return;
    }

    std::wstring err;
    long rc = CallRpcLogin(u, p, err);
    SetWindowTextW(hEditPass, L"");
    if (rc != 0) {
        std::wstring msg = L"\x041E\x0448\x0438\x0431\x043A\x0430: " + (err.empty() ? L"\x043D\x0435\x0432\x0435\x0440\x043D\x044B\x0435 \x0434\x0430\x043D\x043D\x044B\x0435" : err); // Ошибка: ...
        SetWindowTextW(hLblLoginErr, msg.c_str());
        SetView(View::Login);   // explicitly re-show login
        return;
    }
    SetWindowTextW(hLblLoginErr, L"");
    RefreshView();
}

static void OnActivateClick(HWND hWnd)
{
    wchar_t code[256] = {};
    GetWindowTextW(hEditActCode, code, _countof(code));
    if (!*code) {
        SetWindowTextW(hLblActErr,
            L"\x0412\x0432\x0435\x0434\x0438\x0442\x0435 \x043A\x043E\x0434"); // Введите код
        return;
    }

    std::wstring err;
    long rc = CallRpcActivate(code, err);
    if (rc != 0) {
        std::wstring msg = L"\x041E\x0448\x0438\x0431\x043A\x0430 \x0430\x043A\x0442\x0438\x0432\x0430\x0446\x0438\x0438: " + // Ошибка активации:
                           (err.empty() ? L"\x043D\x0435\x0432\x0435\x0440\x043D\x044B\x0439 \x043A\x043E\x0434" : err); // неверный код
        SetWindowTextW(hLblActErr, msg.c_str());
        SetView(View::Activation);
        return;
    }
    SetWindowTextW(hLblActErr, L"");
    SetWindowTextW(hEditActCode, L"");
    RefreshView();
}

static void OnLogout(HWND hWnd)
{
    CallRpcLogout();
    g_authenticated = false; g_hasLicense = false;
    g_username.clear(); g_licenseExpiry.clear();
    RefreshView();
    ShowMainWindow(hWnd);
}

/* ── Антивирусные действия ─────────────────────────────────────── */

static bool ChooseFileDialog(HWND owner, std::wstring& outPath)
{
    wchar_t buf[MAX_PATH] = {};
    OPENFILENAMEW ofn = { sizeof(ofn) };
    ofn.hwndOwner   = owner;
    ofn.lpstrFile   = buf;
    ofn.nMaxFile    = MAX_PATH;
    ofn.lpstrFilter = L"All files\0*.*\0";
    ofn.Flags       = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    if (!GetOpenFileNameW(&ofn)) return false;
    outPath = buf;
    return true;
}

static bool ChooseFolderDialog(HWND owner, std::wstring& outPath)
{
    BROWSEINFOW bi = {};
    bi.hwndOwner = owner;
    bi.lpszTitle = L"\x0412\x044B\x0431\x0435\x0440\x0438\x0442\x0435 \x043F\x0430\x043F\x043A\x0443"; // Выберите папку
    bi.ulFlags   = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
    LPITEMIDLIST pidl = SHBrowseForFolderW(&bi);
    if (!pidl) return false;
    wchar_t path[MAX_PATH] = {};
    BOOL ok = SHGetPathFromIDListW(pidl, path);
    CoTaskMemFree(pidl);
    if (!ok) return false;
    outPath = path;
    return true;
}

static void OnScanFile(HWND hWnd)
{
    std::wstring path;
    if (!ChooseFileDialog(hWnd, path)) return;

    std::wstring res;
    long rc = CallRpcScanFile(path, res);
    if (rc != 0) {
        MessageBoxW(hWnd, res.empty() ? L"\x041E\x0448\x0438\x0431\x043A\x0430" : res.c_str(),
                    L"\x0421\x043A\x0430\x043D\x0438\x0440\x043E\x0432\x0430\x043D\x0438\x0435", MB_OK | MB_ICONWARNING);
        return;
    }

    std::wstring msg;
    if (res.rfind(L"infected|", 0) == 0) {
        msg = L"\x041E\x0431\x043D\x0430\x0440\x0443\x0436\x0435\x043D\x0430 \x0443\x0433\x0440\x043E\x0437\x0430!\n\n"; // Обнаружена угроза!
        msg += L"\x0424\x0430\x0439\x043B: " + path + L"\n";   // Файл:
        msg += L"\x0414\x0435\x0442\x0430\x043B\x0438: " + res.substr(9);   // Детали:
        MessageBoxW(hWnd, msg.c_str(), L"\x0410\x043D\x0442\x0438\x0432\x0438\x0440\x0443\x0441", MB_OK | MB_ICONERROR);
    } else if (res == L"clean") {
        msg = L"\x0424\x0430\x0439\x043B \x0447\x0438\x0441\x0442: " + path; // Файл чист:
        MessageBoxW(hWnd, msg.c_str(), L"\x0410\x043D\x0442\x0438\x0432\x0438\x0440\x0443\x0441", MB_OK | MB_ICONINFORMATION);
    } else {
        MessageBoxW(hWnd, res.c_str(), L"\x0410\x043D\x0442\x0438\x0432\x0438\x0440\x0443\x0441", MB_OK | MB_ICONWARNING);
    }
}

static void OnScanDirectory(HWND hWnd)
{
    std::wstring path;
    if (!ChooseFolderDialog(hWnd, path)) return;

    std::wstring res;
    long rc = CallRpcScanDirectory(path, res);
    if (rc != 0) {
        MessageBoxW(hWnd, res.empty() ? L"\x041E\x0448\x0438\x0431\x043A\x0430" : res.c_str(),
                    L"\x0421\x043A\x0430\x043D\x0438\x0440\x043E\x0432\x0430\x043D\x0438\x0435", MB_OK | MB_ICONWARNING);
        return;
    }

    if (res == L"clean") {
        MessageBoxW(hWnd,
            L"\x0423\x0433\x0440\x043E\x0437 \x043D\x0435 \x043E\x0431\x043D\x0430\x0440\x0443\x0436\x0435\x043D\x043E", // Угроз не обнаружено
            L"\x0410\x043D\x0442\x0438\x0432\x0438\x0440\x0443\x0441", MB_OK | MB_ICONINFORMATION);
    } else {
        std::wstring msg = L"\x041E\x0431\x043D\x0430\x0440\x0443\x0436\x0435\x043D\x044B \x0443\x0433\x0440\x043E\x0437\x044B:\n\n"; // Обнаружены угрозы:
        msg += res;
        MessageBoxW(hWnd, msg.c_str(), L"\x0410\x043D\x0442\x0438\x0432\x0438\x0440\x0443\x0441", MB_OK | MB_ICONERROR);
    }
}

static void OnScanAllDrives(HWND hWnd)
{
    int r = MessageBoxW(hWnd,
        L"\x041D\x0430\x0447\x0430\x0442\x044C \x0441\x043A\x0430\x043D\x0438\x0440\x043E\x0432\x0430\x043D\x0438\x0435 \x0432\x0441\x0435\x0445 \x0434\x0438\x0441\x043A\x043E\x0432?\n\n\x042D\x0442\x043E \x043C\x043E\x0436\x0435\x0442 \x0437\x0430\x043D\x044F\x0442\x044C \x0432\x0440\x0435\x043C\x044F.", // Начать сканирование всех дисков?
        L"\x0410\x043D\x0442\x0438\x0432\x0438\x0440\x0443\x0441", MB_YESNO | MB_ICONQUESTION);
    if (r != IDYES) return;

    std::wstring res;
    long rc = CallRpcScanAllDrives(res);
    if (rc != 0) {
        MessageBoxW(hWnd, res.empty() ? L"\x041E\x0448\x0438\x0431\x043A\x0430" : res.c_str(),
                    L"\x0421\x043A\x0430\x043D\x0438\x0440\x043E\x0432\x0430\x043D\x0438\x0435", MB_OK | MB_ICONWARNING);
        return;
    }
    if (res == L"clean") {
        MessageBoxW(hWnd,
            L"\x0423\x0433\x0440\x043E\x0437 \x043D\x0435 \x043E\x0431\x043D\x0430\x0440\x0443\x0436\x0435\x043D\x043E",
            L"\x0410\x043D\x0442\x0438\x0432\x0438\x0440\x0443\x0441", MB_OK | MB_ICONINFORMATION);
    } else {
        std::wstring msg = L"\x041E\x0431\x043D\x0430\x0440\x0443\x0436\x0435\x043D\x044B \x0443\x0433\x0440\x043E\x0437\x044B:\n\n";
        msg += res;
        MessageBoxW(hWnd, msg.c_str(), L"\x0410\x043D\x0442\x0438\x0432\x0438\x0440\x0443\x0441", MB_OK | MB_ICONERROR);
    }
}

/* ================================================================ */
/*  Window procedure                                                 */
/* ================================================================ */

static LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (msg == WM_TASKBARCREATED && WM_TASKBARCREATED != 0) {
        AddTrayIcon(hWnd); return 0;
    }

    switch (msg) {
    case WM_CREATE:
        SetMenu(hWnd, CreateMainMenu());
        AddTrayIcon(hWnd);
        CreateAllControls(hWnd);
        RefreshView();
        if (!g_showOnStart) ShowWindow(hWnd, SW_HIDE);
        g_pollTimer = SetTimer(hWnd, 1, 5000, nullptr);  // poll license/auth every 5s
        return 0;

    case WM_TIMER:
        if (wParam == 1) RefreshView();
        return 0;

    case WM_REFRESH_VIEW:
        RefreshView();
        return 0;

    case WM_TRAYICON:
        if (lParam == WM_LBUTTONUP)      ShowMainWindow(hWnd);
        else if (lParam == WM_RBUTTONUP) ShowTrayContextMenu(hWnd);
        return 0;

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case ID_FILE_EXIT:
        case ID_TRAY_EXIT:
            ExitApp(hWnd); return 0;
        case ID_TRAY_OPEN:
            ShowMainWindow(hWnd); return 0;
        case ID_FILE_LOGOUT:
            OnLogout(hWnd); return 0;
        case IDC_LOGIN_OK:
            OnLoginClick(hWnd); return 0;
        case IDC_ACT_OK:
            OnActivateClick(hWnd); return 0;
        case ID_AV_SCAN_FILE:
            OnScanFile(hWnd); return 0;
        case ID_AV_SCAN_DIR:
            OnScanDirectory(hWnd); return 0;
        case ID_AV_SCAN_ALL:
            OnScanAllDrives(hWnd); return 0;
        }
        break;

    case WM_CLOSE:
        ShowWindow(hWnd, SW_HIDE);
        return 0;

    case WM_DESTROY:
        if (g_pollTimer) KillTimer(hWnd, g_pollTimer);
        UnbindRpc();
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
    /* Специальный режим для деинсталлятора: остановить службу через RPC и выйти.
       Используется в [UninstallRun] инсталлятора, т.к. защита процессов
       блокирует обычный taskkill. Бесшумно, без UI. */
    if (lpCmdLine && wcsstr(lpCmdLine, L"--stop-service")) {
        if (IsServiceRunning()) {
            CallRpcStopService();
            Sleep(3000);    // ждём пока служба корректно остановится
        }
        return 0;
    }

    if (!IsServiceRunning()) { TryStartService(); return 0; }
    if (!IsParentService())  { return 0; }

    HANDLE hMutex = CreateMutexW(nullptr, TRUE, MUTEX_NAME);
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        if (hMutex) CloseHandle(hMutex);
        return 0;
    }

    /* Доп: защита клиентского процесса от завершения через taskkill */
    ProtectCurrentProcessFromTermination();

    if (lpCmdLine && wcsstr(lpCmdLine, L"--hidden")) g_showOnStart = false;

    INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_STANDARD_CLASSES };
    InitCommonControlsEx(&icc);
    WM_TASKBARCREATED = RegisterWindowMessageW(L"TaskbarCreated");

    WNDCLASSEXW wc = {};
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInstance;
    wc.hIcon         = LoadIconW(hInstance, MAKEINTRESOURCEW(IDI_TRAYAPP));
    wc.hCursor       = LoadCursorW(nullptr, (LPCWSTR)IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = CLASS_NAME;
    RegisterClassExW(&wc);

    g_hWnd = CreateWindowExW(0, CLASS_NAME, L"TrayApp",
        WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 640, 320,
        nullptr, nullptr, hInstance, nullptr);

    if (!g_hWnd) { CloseHandle(hMutex); return 1; }

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
