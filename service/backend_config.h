#pragma once

/* Adjust to match your backend.
   The endpoints are relative to BACKEND_BASE_URL. */

#define BACKEND_BASE_URL        L"https://localhost:8443"

#define EP_LOGIN                L"/api/auth/login"      // POST {username, password}
#define EP_REFRESH              L"/api/auth/refresh"    // POST {refreshToken}
#define EP_LOGOUT               L"/api/auth/logout"     // POST (bearer)
#define EP_LICENSE_CHECK        L"/api/license/check"   // GET  (bearer)
#define EP_LICENSE_ACTIVATE     L"/api/license/activate"// POST {code} (bearer)

/* JSON field names returned by the backend */
#define J_ACCESS_TOKEN          "accessToken"
#define J_REFRESH_TOKEN         "refreshToken"
#define J_ACCESS_EXPIRES_IN     "accessTokenExpiresIn"  // seconds
#define J_REFRESH_EXPIRES_IN    "refreshTokenExpiresIn" // seconds
#define J_USERNAME              "username"
#define J_HAS_LICENSE           "hasLicense"
#define J_EXPIRATION_DATE       "expirationDate"
#define J_LICENSE_TICKET        "ticket"                // present in activation response
