#include "http_client.h"
#include <windows.h>
#include <winhttp.h>
#include <vector>

#pragma comment(lib, "winhttp.lib")

HttpResponse HttpRequest(const std::wstring& method,
                         const std::wstring& url,
                         const std::string&  body,
                         const std::string&  bearer)
{
    HttpResponse out;

    URL_COMPONENTSW comp = {};
    comp.dwStructSize = sizeof(comp);
    wchar_t host[256] = {};
    wchar_t path[1024] = {};
    comp.lpszHostName  = host; comp.dwHostNameLength  = _countof(host);
    comp.lpszUrlPath   = path; comp.dwUrlPathLength   = _countof(path);

    if (!WinHttpCrackUrl(url.c_str(), 0, 0, &comp)) return out;

    HINTERNET hSession = WinHttpOpen(L"TrayService/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return out;

    HINTERNET hConnect = WinHttpConnect(hSession, host, comp.nPort, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return out; }

    DWORD flags = (comp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, method.c_str(), path,
        nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return out;
    }

    /* Allow self-signed / dev certs (common for local backend) */
    if (flags & WINHTTP_FLAG_SECURE) {
        DWORD secFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA
                       | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
                       | SECURITY_FLAG_IGNORE_CERT_CN_INVALID
                       | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS,
                         &secFlags, sizeof(secFlags));
    }

    std::wstring headers = L"Content-Type: application/json\r\n";
    if (!bearer.empty()) {
        std::wstring w(bearer.begin(), bearer.end());
        headers += L"Authorization: Bearer " + w + L"\r\n";
    }

    BOOL sent = WinHttpSendRequest(hRequest,
        headers.c_str(), (DWORD)headers.size(),
        body.empty() ? WINHTTP_NO_REQUEST_DATA : (LPVOID)body.data(),
        (DWORD)body.size(), (DWORD)body.size(), 0);

    if (sent && WinHttpReceiveResponse(hRequest, nullptr)) {
        DWORD status = 0; DWORD szLen = sizeof(status);
        WinHttpQueryHeaders(hRequest,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX, &status, &szLen, WINHTTP_NO_HEADER_INDEX);
        out.statusCode = (long)status;

        DWORD avail = 0;
        while (WinHttpQueryDataAvailable(hRequest, &avail) && avail > 0) {
            std::vector<char> buf(avail);
            DWORD read = 0;
            WinHttpReadData(hRequest, buf.data(), avail, &read);
            out.body.append(buf.data(), read);
        }
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return out;
}
