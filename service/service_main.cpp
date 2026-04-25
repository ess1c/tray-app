#include <windows.h>
#include <wtsapi32.h>
#include <userenv.h>
#include <vector>
#include <string>
#include <mutex>
#include <atomic>
#include <thread>
#include <cstdlib>
#include "trayapp_h.h"
#include "http_client.h"
#include "json_lite.h"
#include "backend_config.h"

#pragma comment(lib, "rpcrt4.lib")
#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "userenv.lib")

/* ================================================================ */
/*  Service constants                                                */
/* ================================================================ */

static const wchar_t* SERVICE_NAME = L"TrayAppService";
static const wchar_t* RPC_ENDPOINT = L"TrayAppRpcEndpoint";

static SERVICE_STATUS_HANDLE g_hStatus = nullptr;
static SERVICE_STATUS        g_status  = {};

struct ProcessEntry { DWORD pid; HANDLE hProcess; };
static std::vector<ProcessEntry> g_processes;
static CRITICAL_SECTION          g_cs;

/* ================================================================ */
/*  Auth + license state (in memory only — never on disk)            */
/* ================================================================ */

struct State {
    std::string  accessToken;
    std::string  refreshToken;
    std::string  username;
    long long    accessExpiresAt   = 0; // unix time
    long long    refreshExpiresAt  = 0;

    bool         hasLicense        = false;
    std::string  licenseTicket;          // never sent to clients
    std::string  expirationDate;         // exposed
    long long    licenseRefreshAt  = 0;  // unix time
};

static std::mutex     g_stateMu;
static State          g_state;

static HANDLE         g_hStopEvent     = nullptr;     // signals background threads to exit
static std::thread    g_tokenThread;
static std::thread    g_licenseThread;
static std::atomic<bool> g_threadsRunning{false};

/* ================================================================ */
/*  Forward declarations                                             */
/* ================================================================ */

void  WINAPI ServiceMain(DWORD argc, LPWSTR* argv);
DWORD WINAPI ServiceCtrlHandler(DWORD control, DWORD eventType,
                                LPVOID eventData, LPVOID context);
void  LaunchInSession(DWORD sessionId);
void  LaunchInAllSessions();
void  TerminateAllLaunched();
void  StartRpcServer();
void  ReportStatus(DWORD state);

static bool DoRefreshTokens();
static bool DoFetchLicense();
static void StartBackgroundThreads();
static void StopBackgroundThreads();

/* ================================================================ */
/*  Helpers                                                          */
/* ================================================================ */

static long long Now()
{
    return (long long)time(nullptr);
}

static std::wstring BuildUrl(const wchar_t* path)
{
    std::wstring s = BACKEND_BASE_URL;
    s += path;
    return s;
}

static std::string EscapeJson(const std::string& s)
{
    std::string r;
    for (char c : s) {
        if (c == '\\' || c == '"') { r += '\\'; r += c; }
        else if (c == '\n') r += "\\n";
        else if (c == '\r') r += "\\r";
        else if (c == '\t') r += "\\t";
        else r += c;
    }
    return r;
}

static std::string WideToUtf8(const wchar_t* w)
{
    if (!w) return "";
    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 1) return "";
    std::string s(n - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, -1, s.data(), n, nullptr, nullptr);
    return s;
}

static std::wstring Utf8ToWide(const std::string& s)
{
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    if (n <= 0) return L"";
    std::wstring w(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), w.data(), n);
    return w;
}

/* MIDL-allocated wide string copy for [out] parameters */
static wchar_t* MidlCopy(const std::wstring& s)
{
    size_t bytes = (s.size() + 1) * sizeof(wchar_t);
    wchar_t* p = (wchar_t*)midl_user_allocate(bytes);
    if (!p) return nullptr;
    memcpy(p, s.c_str(), bytes);
    return p;
}

/* ================================================================ */
/*  Auth + license operations (run inside locked sections)           */
/* ================================================================ */

static bool ApplyTokenResponse(const std::string& body)
{
    std::string at = JsonString(body, J_ACCESS_TOKEN);
    std::string rt = JsonString(body, J_REFRESH_TOKEN);
    if (at.empty() || rt.empty()) return false;

    long long aExp = JsonNumber(body, J_ACCESS_EXPIRES_IN, 900);   // default 15 min
    long long rExp = JsonNumber(body, J_REFRESH_EXPIRES_IN, 86400);// default 24 h
    std::string uname = JsonString(body, J_USERNAME);

    std::lock_guard<std::mutex> lk(g_stateMu);
    g_state.accessToken      = at;
    g_state.refreshToken     = rt;
    g_state.accessExpiresAt  = Now() + aExp;
    g_state.refreshExpiresAt = Now() + rExp;
    if (!uname.empty()) g_state.username = uname;
    return true;
}

static bool DoLogin(const std::string& username, const std::string& password,
                    std::string& outError)
{
    std::string body = "{\"username\":\"" + EscapeJson(username) +
                       "\",\"password\":\"" + EscapeJson(password) + "\"}";
    HttpResponse r = HttpRequest(L"POST", BuildUrl(EP_LOGIN), body, "");

    if (!r.ok()) {
        outError = (r.statusCode == 0) ? "no connection to backend"
                                       : "auth failed (HTTP " + std::to_string(r.statusCode) + ")";
        return false;
    }

    if (!ApplyTokenResponse(r.body)) {
        outError = "invalid response from backend";
        return false;
    }

    {
        std::lock_guard<std::mutex> lk(g_stateMu);
        if (g_state.username.empty()) g_state.username = username;
    }
    return true;
}

static bool DoRefreshTokens()
{
    std::string rt;
    {
        std::lock_guard<std::mutex> lk(g_stateMu);
        rt = g_state.refreshToken;
    }
    if (rt.empty()) return false;

    std::string body = "{\"refreshToken\":\"" + EscapeJson(rt) + "\"}";
    HttpResponse r = HttpRequest(L"POST", BuildUrl(EP_REFRESH), body, "");
    if (!r.ok()) return false;
    return ApplyTokenResponse(r.body);
}

static bool DoFetchLicense()
{
    std::string at;
    {
        std::lock_guard<std::mutex> lk(g_stateMu);
        at = g_state.accessToken;
    }
    if (at.empty()) return false;

    HttpResponse r = HttpRequest(L"GET", BuildUrl(EP_LICENSE_CHECK), "", at);

    std::lock_guard<std::mutex> lk(g_stateMu);
    if (!r.ok()) {
        /* Treat 404 / 4xx as "no license" rather than network error */
        if (r.statusCode >= 400 && r.statusCode < 500) {
            g_state.hasLicense = false;
            g_state.licenseTicket.clear();
            g_state.expirationDate.clear();
            g_state.licenseRefreshAt = Now() + 60;
        }
        return false;
    }

    std::string ticket = JsonString(r.body, J_LICENSE_TICKET);
    std::string exp    = JsonString(r.body, J_EXPIRATION_DATE);
    bool has           = JsonBool(r.body, J_HAS_LICENSE, !ticket.empty());

    if (has) {
        g_state.hasLicense       = true;
        g_state.licenseTicket    = ticket.empty() ? r.body : ticket;
        g_state.expirationDate   = exp;
        g_state.licenseRefreshAt = Now() + 600; // re-check every 10 min
        return true;
    }

    g_state.hasLicense = false;
    g_state.licenseTicket.clear();
    g_state.expirationDate.clear();
    g_state.licenseRefreshAt = Now() + 60;
    return false;
}

static bool DoActivate(const std::string& code, std::string& outError)
{
    std::string at;
    {
        std::lock_guard<std::mutex> lk(g_stateMu);
        at = g_state.accessToken;
    }
    if (at.empty()) { outError = "not authenticated"; return false; }

    std::string body = "{\"code\":\"" + EscapeJson(code) + "\"}";
    HttpResponse r = HttpRequest(L"POST", BuildUrl(EP_LICENSE_ACTIVATE), body, at);
    if (!r.ok()) {
        outError = (r.statusCode == 0) ? "no connection to backend"
                                       : "activation failed (HTTP " + std::to_string(r.statusCode) + ")";
        return false;
    }

    std::string ticket = JsonString(r.body, J_LICENSE_TICKET);
    if (!ticket.empty()) {
        std::lock_guard<std::mutex> lk(g_stateMu);
        g_state.hasLicense       = true;
        g_state.licenseTicket    = ticket;
        g_state.expirationDate   = JsonString(r.body, J_EXPIRATION_DATE);
        g_state.licenseRefreshAt = Now() + 600;
        return true;
    }

    /* If activation didn't return a ticket — fetch it explicitly */
    if (!DoFetchLicense()) {
        outError = "activated but license check failed";
        return false;
    }
    return true;
}

static void DoLogout()
{
    std::string at;
    {
        std::lock_guard<std::mutex> lk(g_stateMu);
        at = g_state.accessToken;
    }
    if (!at.empty()) {
        HttpRequest(L"POST", BuildUrl(EP_LOGOUT), "", at);
    }

    std::lock_guard<std::mutex> lk(g_stateMu);
    g_state = State{};
}

/* ================================================================ */
/*  Background threads                                               */
/* ================================================================ */

static void TokenRefreshThread()
{
    while (true) {
        long long now = Now();
        long long sleepFor = 30; // default poll interval

        {
            std::lock_guard<std::mutex> lk(g_stateMu);
            if (!g_state.accessToken.empty()) {
                long long until = g_state.accessExpiresAt - now;
                /* refresh when 60s remain, but at least every 30s */
                sleepFor = (until > 90) ? (until - 60) : 1;
            }
        }

        DWORD waited = WaitForSingleObject(g_hStopEvent, (DWORD)(sleepFor * 1000));
        if (waited == WAIT_OBJECT_0) return;

        bool needRefresh = false;
        {
            std::lock_guard<std::mutex> lk(g_stateMu);
            needRefresh = !g_state.accessToken.empty() &&
                          (Now() + 60 >= g_state.accessExpiresAt);
        }
        if (needRefresh) DoRefreshTokens();
    }
}

static void LicenseRefreshThread()
{
    while (true) {
        DWORD waited = WaitForSingleObject(g_hStopEvent, 30000);
        if (waited == WAIT_OBJECT_0) return;

        bool needFetch = false;
        bool authed    = false;
        {
            std::lock_guard<std::mutex> lk(g_stateMu);
            authed     = !g_state.accessToken.empty();
            needFetch  = authed && Now() >= g_state.licenseRefreshAt;
        }
        if (needFetch) DoFetchLicense();
    }
}

static void StartBackgroundThreads()
{
    if (g_threadsRunning.exchange(true)) return;
    if (!g_hStopEvent) g_hStopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    g_tokenThread   = std::thread(TokenRefreshThread);
    g_licenseThread = std::thread(LicenseRefreshThread);
}

static void StopBackgroundThreads()
{
    if (!g_threadsRunning.exchange(false)) return;
    if (g_hStopEvent) SetEvent(g_hStopEvent);
    if (g_tokenThread.joinable())   g_tokenThread.join();
    if (g_licenseThread.joinable()) g_licenseThread.join();
    if (g_hStopEvent) { CloseHandle(g_hStopEvent); g_hStopEvent = nullptr; }
}

/* ================================================================ */
/*  RPC server-side implementation                                   */
/* ================================================================ */

void RpcStopService(void)
{
    RpcMgmtStopServerListening(nullptr);
}

long RpcLogin(const wchar_t* username, const wchar_t* password,
              wchar_t** errorMessage)
{
    *errorMessage = nullptr;
    std::string err;
    if (!DoLogin(WideToUtf8(username), WideToUtf8(password), err)) {
        *errorMessage = MidlCopy(Utf8ToWide(err));
        return 4;
    }
    /* Try to fetch license right away (non-fatal if it fails) */
    DoFetchLicense();
    return 0;
}

long RpcLogout(void)
{
    DoLogout();
    return 0;
}

long RpcGetCurrentUser(long* isAuthenticated, wchar_t** username)
{
    std::lock_guard<std::mutex> lk(g_stateMu);
    *isAuthenticated = g_state.accessToken.empty() ? 0 : 1;
    *username = MidlCopy(Utf8ToWide(g_state.username));
    return 0;
}

long RpcGetLicenseStatus(long* hasLicense, wchar_t** expirationDate,
                         wchar_t** errorMessage)
{
    *hasLicense = 0; *expirationDate = nullptr; *errorMessage = nullptr;

    {
        std::lock_guard<std::mutex> lk(g_stateMu);
        if (g_state.accessToken.empty()) {
            *errorMessage = MidlCopy(L"not authenticated");
            return 1;
        }
        if (g_state.hasLicense) {
            *hasLicense = 1;
            *expirationDate = MidlCopy(Utf8ToWide(g_state.expirationDate));
            return 0;
        }
    }

    /* No license cached — try to fetch */
    DoFetchLicense();

    std::lock_guard<std::mutex> lk(g_stateMu);
    if (g_state.hasLicense) {
        *hasLicense = 1;
        *expirationDate = MidlCopy(Utf8ToWide(g_state.expirationDate));
        return 0;
    }
    *errorMessage = MidlCopy(L"no license");
    return 2;
}

long RpcActivate(const wchar_t* code, wchar_t** errorMessage)
{
    *errorMessage = nullptr;

    {
        std::lock_guard<std::mutex> lk(g_stateMu);
        if (g_state.accessToken.empty()) {
            *errorMessage = MidlCopy(L"not authenticated");
            return 1;
        }
    }

    std::string err;
    if (!DoActivate(WideToUtf8(code), err)) {
        *errorMessage = MidlCopy(Utf8ToWide(err));
        return 4;
    }
    return 0;
}

void* __RPC_USER midl_user_allocate(size_t size) { return malloc(size); }
void  __RPC_USER midl_user_free(void* p)         { free(p); }

/* ================================================================ */
/*  Service plumbing                                                 */
/* ================================================================ */

int wmain()
{
    SERVICE_TABLE_ENTRYW table[] = {
        { const_cast<LPWSTR>(SERVICE_NAME), ServiceMain },
        { nullptr, nullptr }
    };
    StartServiceCtrlDispatcherW(table);
    return 0;
}

void WINAPI ServiceMain(DWORD, LPWSTR*)
{
    InitializeCriticalSection(&g_cs);

    g_hStatus = RegisterServiceCtrlHandlerExW(SERVICE_NAME,
                                              ServiceCtrlHandler, nullptr);
    if (!g_hStatus) return;

    ReportStatus(SERVICE_START_PENDING);

    LaunchInAllSessions();
    StartBackgroundThreads();

    ReportStatus(SERVICE_RUNNING);

    StartRpcServer();           // blocking

    StopBackgroundThreads();
    DoLogout();                 // wipe tokens/ticket from memory
    TerminateAllLaunched();

    ReportStatus(SERVICE_STOPPED);
    DeleteCriticalSection(&g_cs);
}

DWORD WINAPI ServiceCtrlHandler(DWORD control, DWORD eventType,
                                LPVOID eventData, LPVOID)
{
    switch (control) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        return ERROR_CALL_NOT_IMPLEMENTED;

    case SERVICE_CONTROL_SESSIONCHANGE:
        if (eventType == WTS_SESSION_LOGON) {
            auto* sn = reinterpret_cast<WTSSESSION_NOTIFICATION*>(eventData);
            LaunchInSession(sn->dwSessionId);
        }
        return NO_ERROR;

    case SERVICE_CONTROL_INTERROGATE:
        return NO_ERROR;

    default:
        return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

void ReportStatus(DWORD state)
{
    g_status.dwServiceType   = SERVICE_WIN32_OWN_PROCESS;
    g_status.dwCurrentState  = state;
    g_status.dwWin32ExitCode = 0;
    g_status.dwCheckPoint    = 0;
    g_status.dwWaitHint      = 0;
    g_status.dwControlsAccepted =
        (state == SERVICE_RUNNING) ? SERVICE_ACCEPT_SESSIONCHANGE : 0;
    SetServiceStatus(g_hStatus, &g_status);
}

void LaunchInSession(DWORD sessionId)
{
    if (sessionId == 0) return;

    HANDLE hToken = nullptr;
    if (!WTSQueryUserToken(sessionId, &hToken)) return;

    HANDLE hDup = nullptr;
    if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, nullptr,
                          SecurityIdentification, TokenPrimary, &hDup)) {
        CloseHandle(hToken); return;
    }
    CloseHandle(hToken);

    LPVOID pEnv = nullptr;
    CreateEnvironmentBlock(&pEnv, hDup, FALSE);

    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    wchar_t* slash = wcsrchr(exePath, L'\\');
    if (slash) wcscpy_s(slash + 1,
                        MAX_PATH - static_cast<size_t>(slash - exePath + 1),
                        L"TrayApp.exe");

    wchar_t cmdLine[MAX_PATH + 32];
    swprintf_s(cmdLine, L"\"%s\" --hidden", exePath);

    STARTUPINFOW si = { sizeof(si) };
    si.lpDesktop = const_cast<LPWSTR>(L"winsta0\\default");
    PROCESS_INFORMATION pi = {};

    if (CreateProcessAsUserW(hDup, nullptr, cmdLine, nullptr, nullptr, FALSE,
                             CREATE_UNICODE_ENVIRONMENT, pEnv, nullptr, &si, &pi)) {
        EnterCriticalSection(&g_cs);
        g_processes.push_back({ pi.dwProcessId, pi.hProcess });
        LeaveCriticalSection(&g_cs);
        CloseHandle(pi.hThread);
    }

    if (pEnv) DestroyEnvironmentBlock(pEnv);
    CloseHandle(hDup);
}

void LaunchInAllSessions()
{
    WTS_SESSION_INFOW* sessions = nullptr;
    DWORD count = 0;
    if (WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &sessions, &count)) {
        for (DWORD i = 0; i < count; i++) {
            if (sessions[i].SessionId != 0 && sessions[i].State == WTSActive) {
                LaunchInSession(sessions[i].SessionId);
            }
        }
        WTSFreeMemory(sessions);
    }
}

void TerminateAllLaunched()
{
    EnterCriticalSection(&g_cs);
    for (auto& p : g_processes) {
        TerminateProcess(p.hProcess, 0);
        CloseHandle(p.hProcess);
    }
    g_processes.clear();
    LeaveCriticalSection(&g_cs);
}

void StartRpcServer()
{
    RpcServerUseProtseqEpW(
        reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(L"ncalrpc")),
        RPC_C_PROTSEQ_MAX_REQS_DEFAULT,
        reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(RPC_ENDPOINT)),
        nullptr);
    RpcServerRegisterIf(TrayAppRpc_v1_0_s_ifspec, nullptr, nullptr);
    RpcServerListen(1, RPC_C_LISTEN_MAX_CALLS_DEFAULT, FALSE);
}
