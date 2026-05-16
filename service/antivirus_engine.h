#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <map>
#include <mutex>

/* Типы сканируемых объектов (обязательно PE + ещё хотя бы один) */
enum class ObjectType : uint8_t {
    Unknown    = 0,
    PE         = 1,   // Windows .exe / .dll (начинаются с MZ)
    JavaScript = 2,   // .js
    PowerShell = 3,   // .ps1
    TextFile   = 4    // .txt и любые текстовые
};

/* Запись антивирусной базы согласно требованию задания.
   Хранится в std::map по ключу = первые 8 байт сигнатуры. */
struct AvRecord {
    uint64_t              signaturePrefix;   // 8 байт: первые 8 байт сигнатуры
    uint32_t              signatureLength;   // 4 байт: полная длина сигнатуры
    std::vector<uint8_t>  signature;         // SHA-256 хеш всей сигнатуры
    uint64_t              offsetBegin;       // начало интервала в файле
    uint64_t              offsetEnd;         // конец интервала в файле
    ObjectType            objectType;        // тип объекта
    std::vector<uint8_t>  recordSignature;   // HMAC-SHA256 всех полей записи (ЭЦП)
    std::string           threatName;        // имя угрозы для отображения
};

/* Результат сканирования */
struct ScanResult {
    std::wstring filePath;
    bool         infected = false;
    std::string  threatName;
    uint64_t     offset = 0;
    bool         error = false;
    std::string  errorMessage;
};

/* Движок сканирования. Базы хранятся только в памяти. */
class AntivirusEngine {
public:
    /* Загрузить встроенные тестовые сигнатуры. Вызывается после успешной активации лицензии. */
    void LoadBuiltinSignatures();

    bool        IsLoaded() const;
    std::string GetReleaseDate() const;
    size_t      GetRecordCount() const;

    /* Сканирование одного файла */
    ScanResult ScanFile(const std::wstring& path);

    /* Сканирование всех файлов в директории (рекурсивно) */
    std::vector<ScanResult> ScanDirectory(const std::wstring& path);

    /* Сканирование всех несъёмных дисков (доп) */
    std::vector<ScanResult> ScanAllFixedDrives();

    void Clear();

private:
    std::map<uint64_t, std::vector<AvRecord>> records_;
    std::string releaseDate_;
    mutable std::mutex mu_;

    bool ScanStream(const uint8_t* data, size_t size, ObjectType type, ScanResult& out) const;
    static std::vector<uint8_t> Sha256(const uint8_t* data, size_t size);
    static std::vector<uint8_t> HmacSha256(const uint8_t* key, size_t keySize,
                                           const uint8_t* data, size_t dataSize);
    static std::vector<uint8_t> SignRecord(const AvRecord& r);
    static ObjectType DetectObjectType(const std::wstring& path);
};
