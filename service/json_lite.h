#pragma once
#include <string>

/* Tiny single-purpose JSON helpers — extract a top-level field by key.
   Good enough for the small schemas this service consumes; not a full parser. */

inline std::string JsonString(const std::string& body, const std::string& key)
{
    std::string needle = "\"" + key + "\"";
    size_t p = body.find(needle);
    if (p == std::string::npos) return "";
    p = body.find(':', p); if (p == std::string::npos) return "";
    p = body.find('"', p); if (p == std::string::npos) return "";
    size_t e = p + 1;
    while (e < body.size() && body[e] != '"') {
        if (body[e] == '\\' && e + 1 < body.size()) e += 2;
        else ++e;
    }
    return body.substr(p + 1, e - p - 1);
}

inline long long JsonNumber(const std::string& body, const std::string& key, long long def = 0)
{
    std::string needle = "\"" + key + "\"";
    size_t p = body.find(needle);
    if (p == std::string::npos) return def;
    p = body.find(':', p); if (p == std::string::npos) return def;
    ++p;
    while (p < body.size() && (body[p] == ' ' || body[p] == '\t')) ++p;
    if (p >= body.size()) return def;
    bool neg = false;
    if (body[p] == '-') { neg = true; ++p; }
    long long n = 0;
    bool any = false;
    while (p < body.size() && body[p] >= '0' && body[p] <= '9') {
        n = n * 10 + (body[p] - '0');
        ++p; any = true;
    }
    if (!any) return def;
    return neg ? -n : n;
}

inline bool JsonBool(const std::string& body, const std::string& key, bool def = false)
{
    std::string needle = "\"" + key + "\"";
    size_t p = body.find(needle);
    if (p == std::string::npos) return def;
    p = body.find(':', p); if (p == std::string::npos) return def;
    ++p;
    while (p < body.size() && (body[p] == ' ' || body[p] == '\t')) ++p;
    if (body.compare(p, 4, "true") == 0)  return true;
    if (body.compare(p, 5, "false") == 0) return false;
    return def;
}
