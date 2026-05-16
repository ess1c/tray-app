#include "antivirus_engine.h"
#include <windows.h>
#include <bcrypt.h>
#include <fileapi.h>
#include <fstream>
#include <ctime>
#include <algorithm>
#include <cstring>

#pragma comment(lib, "bcrypt.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)
#endif

/* HMAC-секретный ключ для подписи записей (ЭЦП в упрощённом варианте).
   В реальном антивирусе подпись делалась бы приватным ключом издателя баз. */
static const uint8_t HMAC_KEY[] = "TrayApp-AV-Signing-Key-v1";

/* ================================================================ */
/*  Crypto helpers (BCrypt SHA-256)                                  */
/* ================================================================ */

std::vector<uint8_t> AntivirusEngine::Sha256(const uint8_t* data, size_t size)
{
    std::vector<uint8_t> hash(32, 0);
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;

    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0)))
        return hash;

    if (NT_SUCCESS(BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0))) {
        BCryptHashData(hHash, (PUCHAR)data, (ULONG)size, 0);
        BCryptFinishHash(hHash, hash.data(), (ULONG)hash.size(), 0);
        BCryptDestroyHash(hHash);
    }
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return hash;
}

std::vector<uint8_t> AntivirusEngine::HmacSha256(const uint8_t* key, size_t keySize,
                                                 const uint8_t* data, size_t dataSize)
{
    std::vector<uint8_t> hash(32, 0);
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;

    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM,
                                                nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG)))
        return hash;

    if (NT_SUCCESS(BCryptCreateHash(hAlg, &hHash, nullptr, 0,
                                     (PUCHAR)key, (ULONG)keySize, 0))) {
        BCryptHashData(hHash, (PUCHAR)data, (ULONG)dataSize, 0);
        BCryptFinishHash(hHash, hash.data(), (ULONG)hash.size(), 0);
        BCryptDestroyHash(hHash);
    }
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return hash;
}

std::vector<uint8_t> AntivirusEngine::SignRecord(const AvRecord& r)
{
    /* Подписываем все поля записи, кроме самой recordSignature.
       Это и есть требование 2.7 — ЭЦП всех полей. */
    std::vector<uint8_t> buf;
    auto append = [&](const void* p, size_t n) {
        const uint8_t* b = (const uint8_t*)p;
        buf.insert(buf.end(), b, b + n);
    };
    append(&r.signaturePrefix, sizeof(r.signaturePrefix));
    append(&r.signatureLength, sizeof(r.signatureLength));
    if (!r.signature.empty())
        append(r.signature.data(), r.signature.size());
    append(&r.offsetBegin, sizeof(r.offsetBegin));
    append(&r.offsetEnd,   sizeof(r.offsetEnd));
    uint8_t ot = (uint8_t)r.objectType;
    append(&ot, 1);

    return HmacSha256(HMAC_KEY, sizeof(HMAC_KEY) - 1, buf.data(), buf.size());
}

/* ================================================================ */
/*  Object type detection by file extension                          */
/* ================================================================ */

ObjectType AntivirusEngine::DetectObjectType(const std::wstring& path)
{
    auto dot = path.find_last_of(L'.');
    if (dot == std::wstring::npos) return ObjectType::TextFile;
    std::wstring ext = path.substr(dot);
    for (auto& c : ext) c = (wchar_t)towlower(c);

    if (ext == L".exe" || ext == L".dll" || ext == L".sys") return ObjectType::PE;
    if (ext == L".js")                                       return ObjectType::JavaScript;
    if (ext == L".ps1")                                      return ObjectType::PowerShell;
    return ObjectType::TextFile;
}

/* ================================================================ */
/*  Loading built-in signatures                                      */
/* ================================================================ */

static uint64_t MakePrefix(const char* str)
{
    /* Первые 8 байт строки в little-endian uint64 */
    uint64_t v = 0;
    for (int i = 0; i < 8 && str[i]; ++i) {
        v |= ((uint64_t)(uint8_t)str[i]) << (8 * i);
    }
    return v;
}

void AntivirusEngine::LoadBuiltinSignatures()
{
    std::lock_guard<std::mutex> lk(mu_);
    records_.clear();

    auto addRecord = [&](const char* fullSig, ObjectType type,
                         uint64_t offBegin, uint64_t offEnd,
                         const char* threatName)
    {
        AvRecord r{};
        r.signaturePrefix  = MakePrefix(fullSig);
        r.signatureLength  = (uint32_t)strlen(fullSig);
        r.signature        = Sha256((const uint8_t*)fullSig, strlen(fullSig));
        r.offsetBegin      = offBegin;
        r.offsetEnd        = offEnd;
        r.objectType       = type;
        r.threatName       = threatName;
        r.recordSignature  = SignRecord(r);
        records_[r.signaturePrefix].push_back(r);
    };

    /* 1. EICAR test signature (текстовый файл) */
    addRecord(
        "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
        ObjectType::TextFile,
        0, 1024,
        "EICAR-Test-File");

    /* 2. Маркер вредоносного PE-файла */
    addRecord(
        "MALICIOUS_TRAYAPP_PE_TEST_MARKER",
        ObjectType::PE,
        0, 65536,
        "TrayApp-Test-Malware-PE");

    /* 3. JS-маркер */
    addRecord(
        "eval('TRAYAPP_TEST_MALWARE_JS')",
        ObjectType::JavaScript,
        0, 8192,
        "TrayApp-Test-Malware-JS");

    /* 4. PowerShell-маркер */
    addRecord(
        "Invoke-TrayAppMalwareTest",
        ObjectType::PowerShell,
        0, 8192,
        "TrayApp-Test-Malware-PS");

    /* Дата выпуска баз */
    time_t now = time(nullptr);
    char buf[32] = {};
    tm tmInfo;
    gmtime_s(&tmInfo, &now);
    strftime(buf, sizeof(buf), "%Y-%m-%d", &tmInfo);
    releaseDate_ = buf;
}

void AntivirusEngine::Clear()
{
    std::lock_guard<std::mutex> lk(mu_);
    records_.clear();
    releaseDate_.clear();
}

bool AntivirusEngine::IsLoaded() const
{
    std::lock_guard<std::mutex> lk(mu_);
    return !records_.empty();
}

std::string AntivirusEngine::GetReleaseDate() const
{
    std::lock_guard<std::mutex> lk(mu_);
    return releaseDate_;
}

size_t AntivirusEngine::GetRecordCount() const
{
    std::lock_guard<std::mutex> lk(mu_);
    size_t total = 0;
    for (const auto& kv : records_) total += kv.second.size();
    return total;
}

/* ================================================================ */
/*  Core scanning algorithm                                          */
/* ================================================================ */

bool AntivirusEngine::ScanStream(const uint8_t* data, size_t size,
                                  ObjectType type, ScanResult& out) const
{
    /* 3.1. Установить позицию в 0; 3.5. сдвигать на 1 байт. */
    for (size_t pos = 0; pos + 8 <= size; ++pos)
    {
        /* 3.2. Считать 8 байт, искать в map */
        uint64_t key = 0;
        memcpy(&key, data + pos, 8);

        auto it = records_.find(key);
        if (it == records_.end()) continue;

        /* 3.3. Для каждой записи — проверки от лёгкой к тяжёлой */
        for (const auto& r : it->second)
        {
            /* 3.3.1. Тип объекта */
            if (r.objectType != type) continue;

            /* 3.3.2. Текущая позиция в диапазоне */
            if (pos < r.offsetBegin || pos > r.offsetEnd) continue;

            /* 3.3.3. Считать ObjectSignatureLength - 8 дополнительных байт */
            if (r.signatureLength < 8) continue;
            size_t extra = r.signatureLength - 8;
            if (pos + 8 + extra > size) continue;

            /* 3.3.4. Хэш от ObjectSignaturePrefix + дополнительные байты */
            std::vector<uint8_t> fullSig(r.signatureLength);
            memcpy(fullSig.data(), &r.signaturePrefix, 8);
            memcpy(fullSig.data() + 8, data + pos + 8, extra);
            auto h = Sha256(fullSig.data(), fullSig.size());

            /* 3.3.5. Сравнить хеши */
            if (h.size() == r.signature.size() &&
                memcmp(h.data(), r.signature.data(), h.size()) == 0)
            {
                /* 3.6. Найдено — объект вредоносный */
                out.infected = true;
                out.threatName = r.threatName;
                out.offset = pos;
                return true;
            }
        }
        /* 3.5. Иначе сдвиг на 1 байт (цикл for) */
    }
    return false;
}

/* ================================================================ */
/*  File / directory scan                                            */
/* ================================================================ */

ScanResult AntivirusEngine::ScanFile(const std::wstring& path)
{
    ScanResult result;
    result.filePath = path;

    if (!IsLoaded()) {
        result.error = true;
        result.errorMessage = "antivirus database not loaded";
        return result;
    }

    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        result.error = true;
        result.errorMessage = "cannot open file";
        return result;
    }

    LARGE_INTEGER fs = {};
    if (!GetFileSizeEx(h, &fs) || fs.QuadPart <= 0 || fs.QuadPart > 100 * 1024 * 1024) {
        CloseHandle(h);
        if (fs.QuadPart > 100 * 1024 * 1024) {
            result.error = true;
            result.errorMessage = "file too large";
        }
        return result;
    }

    std::vector<uint8_t> buf((size_t)fs.QuadPart);
    DWORD readBytes = 0;
    if (!ReadFile(h, buf.data(), (DWORD)buf.size(), &readBytes, nullptr)) {
        CloseHandle(h);
        result.error = true;
        result.errorMessage = "read failed";
        return result;
    }
    CloseHandle(h);

    ObjectType type = DetectObjectType(path);

    std::lock_guard<std::mutex> lk(mu_);
    ScanStream(buf.data(), readBytes, type, result);
    return result;
}

std::vector<ScanResult> AntivirusEngine::ScanDirectory(const std::wstring& path)
{
    std::vector<ScanResult> results;

    std::wstring pattern = path;
    if (!pattern.empty() && pattern.back() != L'\\') pattern += L'\\';
    pattern += L"*";

    WIN32_FIND_DATAW fd = {};
    HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return results;

    do {
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0)
            continue;

        std::wstring full = path;
        if (!full.empty() && full.back() != L'\\') full += L'\\';
        full += fd.cFileName;

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            /* Рекурсивно */
            auto sub = ScanDirectory(full);
            for (auto& r : sub) results.push_back(std::move(r));
        } else {
            ScanResult r = ScanFile(full);
            /* Возвращаем только заражённые и ошибки, чистые скрываем для краткости */
            if (r.infected || r.error) results.push_back(std::move(r));
        }

        if (results.size() > 200) break; // безопасность от слишком больших результатов
    } while (FindNextFileW(h, &fd));

    FindClose(h);
    return results;
}

/* ================================================================ */
/*  Scan all fixed drives (доп)                                      */
/* ================================================================ */

std::vector<ScanResult> AntivirusEngine::ScanAllFixedDrives()
{
    std::vector<ScanResult> results;

    DWORD drives = GetLogicalDrives();
    for (int i = 0; i < 26; ++i) {
        if (!(drives & (1u << i))) continue;
        wchar_t root[4] = { (wchar_t)(L'A' + i), L':', L'\\', 0 };
        if (GetDriveTypeW(root) != DRIVE_FIXED) continue;

        auto sub = ScanDirectory(root);
        for (auto& r : sub) results.push_back(std::move(r));
        if (results.size() > 200) break;
    }
    return results;
}
