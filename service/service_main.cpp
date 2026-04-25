#include <windows.h>
#include <wtsapi32.h>
#include <userenv.h>
#include <vector>
#include <cstdlib>
#include "trayapp_h.h"

#pragma comment(lib, "rpcrt4.lib")
#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "userenv.lib")

static const wchar_t* SERVICE_NAME    = L"TrayAppService";
static const wchar_t* RPC_ENDPOINT    = L"TrayAppRpcEndpoint";

static SERVICE_STATUS_HANDLE g_hStatus = nullptr;
static SERVICE_STATUS        g_status  = {};

struct ProcessEntry { DWORD pid; HANDLE hProcess; };
static std::vector<ProcessEntry> g_processes;
static CRITICAL_SECTION          g_cs;

/* ---------- forward declarations ---------- */
void  WINAPI ServiceMain(DWORD argc, LPWSTR* argv);
DWORD WINAPI ServiceCtrlHandler(DWORD control, DWORD eventType,
                                LPVOID eventData, LPVOID context);
void  LaunchInSession(DWORD sessionId);
void  LaunchInAllSessions();
void  TerminateAllLaunched();
void  StartRpcServer();
void  ReportStatus(DWORD state);

/* ========== RPC server-side implementation ========== */

void RpcStopService(void)
{
    /* Tell the RPC runtime to stop listening.
       RpcServerListen (blocking) will return in ServiceMain. */
    RpcMgmtStopServerListening(nullptr);
}

void* __RPC_USER midl_user_allocate(size_t size) { return malloc(size); }
void  __RPC_USER midl_user_free(void* p)         { free(p); }

/* ========== entry point ========== */

int wmain()
{
    SERVICE_TABLE_ENTRYW table[] = {
        { const_cast<LPWSTR>(SERVICE_NAME), ServiceMain },
        { nullptr, nullptr }
    };
    StartServiceCtrlDispatcherW(table);
    return 0;
}

/* ========== ServiceMain ========== */

void WINAPI ServiceMain(DWORD /*argc*/, LPWSTR* /*argv*/)
{
    InitializeCriticalSection(&g_cs);

    g_hStatus = RegisterServiceCtrlHandlerExW(SERVICE_NAME,
                                              ServiceCtrlHandler, nullptr);
    if (!g_hStatus) return;

    ReportStatus(SERVICE_START_PENDING);

    /* 1. Launch TrayApp in every active user session (except session 0) */
    LaunchInAllSessions();

    ReportStatus(SERVICE_RUNNING);

    /* 2. Block on the RPC server until RpcStopService() is called */
    StartRpcServer();

    /* 3. RPC server has stopped — clean up */
    TerminateAllLaunched();

    ReportStatus(SERVICE_STOPPED);
    DeleteCriticalSection(&g_cs);
}

/* ========== service control handler ========== */

DWORD WINAPI ServiceCtrlHandler(DWORD control, DWORD eventType,
                                LPVOID eventData, LPVOID /*context*/)
{
    switch (control)
    {
    /* Requirement 3: ignore Stop and Shutdown */
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        return ERROR_CALL_NOT_IMPLEMENTED;

    /* Requirement 2: track new logons */
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

/* ========== helpers ========== */

void ReportStatus(DWORD state)
{
    g_status.dwServiceType      = SERVICE_WIN32_OWN_PROCESS;
    g_status.dwCurrentState     = state;
    g_status.dwWin32ExitCode    = 0;
    g_status.dwCheckPoint       = 0;
    g_status.dwWaitHint         = 0;

    if (state == SERVICE_RUNNING)
        g_status.dwControlsAccepted = SERVICE_ACCEPT_SESSIONCHANGE;
    else
        g_status.dwControlsAccepted = 0;

    SetServiceStatus(g_hStatus, &g_status);
}

void LaunchInSession(DWORD sessionId)
{
    if (sessionId == 0) return;

    HANDLE hToken = nullptr;
    if (!WTSQueryUserToken(sessionId, &hToken)) return;

    HANDLE hDup = nullptr;
    if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, nullptr,
                          SecurityIdentification, TokenPrimary, &hDup))
    {
        CloseHandle(hToken);
        return;
    }
    CloseHandle(hToken);

    LPVOID pEnv = nullptr;
    CreateEnvironmentBlock(&pEnv, hDup, FALSE);

    /* Build path to TrayApp.exe next to this service executable */
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
                             CREATE_UNICODE_ENVIRONMENT, pEnv,
                             nullptr, &si, &pi))
    {
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
    if (WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1,
                               &sessions, &count))
    {
        for (DWORD i = 0; i < count; i++) {
            if (sessions[i].SessionId != 0) {
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

    /* Blocking — returns only when RpcMgmtStopServerListening is called */
    RpcServerListen(1, RPC_C_LISTEN_MAX_CALLS_DEFAULT, FALSE);
}
