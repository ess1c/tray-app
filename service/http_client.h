#pragma once
#include <string>

struct HttpResponse {
    long        statusCode = 0;
    std::string body;
    bool        ok() const { return statusCode >= 200 && statusCode < 300; }
};

/* Simple WinHTTP-based HTTPS client.
   `bearer` may be empty — if non-empty, sent as `Authorization: Bearer ...`
   `body` may be empty for GET. Content-Type assumed to be application/json. */

HttpResponse HttpRequest(
    const std::wstring& method,    // L"GET" | L"POST"
    const std::wstring& url,       // full URL
    const std::string&  body,      // JSON body or ""
    const std::string&  bearer     // bearer token or ""
);
