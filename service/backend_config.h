#pragma once

/* Реальный бэкенд из лабораторных работ.
   По умолчанию работает по HTTP на порту 8083.
   Если запущен с профилем ssl — поменяй URL на https://localhost:8083 */

#define BACKEND_BASE_URL        L"http://localhost:8083"

/* Auth */
#define EP_LOGIN                L"/api/auth/login"
#define EP_REFRESH              L"/api/auth/refresh"

/* License */
#define EP_LICENSE_CHECK        L"/api/licenses/check"
#define EP_LICENSE_ACTIVATE     L"/api/licenses/activate"

/* Параметры устройства / продукта (фиксированные для одного клиента) */
#define DEVICE_MAC              "AA:BB:CC:DD:EE:01"
#define DEVICE_NAME             "TrayApp-Workstation"
#define PRODUCT_ID              "1"

/* Token TTL — реальный бэк не возвращает expiresIn в JSON,
   значения берутся из application.properties */
#define DEFAULT_ACCESS_TTL_SEC   900     // 15 минут
#define DEFAULT_REFRESH_TTL_SEC  604800  // 7 дней

/* JSON-поля в ответах */
#define J_ACCESS_TOKEN          "accessToken"
#define J_REFRESH_TOKEN         "refreshToken"
#define J_TICKET                "ticket"
#define J_EXPIRATION_DATE       "expirationDate"
#define J_IS_BLOCKED            "isBlocked"
#define J_TICKET_LIFETIME       "ticketLifetime"
