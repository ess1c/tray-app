#pragma once

#define IDI_TRAYAPP       101

#define ID_FILE_EXIT      40001
#define ID_TRAY_OPEN      40002
#define ID_TRAY_EXIT      40003
#define ID_FILE_LOGOUT    40004

#define WM_TRAYICON       (WM_USER + 1)
#define WM_REFRESH_VIEW   (WM_USER + 2)

/* Login dialog controls */
#define IDC_LOGIN_USER    1001
#define IDC_LOGIN_PASS    1002
#define IDC_LOGIN_OK      1003
#define IDC_LOGIN_ERROR   1004

/* Activation dialog controls (rendered inside main window) */
#define IDC_ACT_CODE      2001
#define IDC_ACT_OK        2002
#define IDC_ACT_ERROR     2003

/* Status labels on main window */
#define IDC_STATUS_USER   3001
#define IDC_STATUS_LIC    3002
#define IDC_STATUS_AV     3003
#define IDC_STATUS_AVDB   3004

/* Antivirus menu items */
#define ID_AV_SCAN_FILE   40010
#define ID_AV_SCAN_DIR    40011
#define ID_AV_SCAN_ALL    40012
