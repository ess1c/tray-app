#pragma once
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>

#pragma comment(lib, "advapi32.lib")

/* Запрещает PROCESS_TERMINATE для всех (включая admin),
   разрешает SYSTEM любые операции.
   Без подписи бинаря (PPL) полная защита от админа невозможна,
   но стандартный taskkill / Process Explorer без отдельных
   ухищрений завершить процесс не смогут. */
inline void ProtectCurrentProcessFromTermination()
{
    PSID systemSid = nullptr;
    PSID everyoneSid = nullptr;

    SID_IDENTIFIER_AUTHORITY nt    = SECURITY_NT_AUTHORITY;
    SID_IDENTIFIER_AUTHORITY world = SECURITY_WORLD_SID_AUTHORITY;

    if (!AllocateAndInitializeSid(&nt, 1, SECURITY_LOCAL_SYSTEM_RID,
                                  0, 0, 0, 0, 0, 0, 0, &systemSid)) return;
    if (!AllocateAndInitializeSid(&world, 1, SECURITY_WORLD_RID,
                                  0, 0, 0, 0, 0, 0, 0, &everyoneSid))
    {
        FreeSid(systemSid);
        return;
    }

    EXPLICIT_ACCESSW ea[3] = {};

    /* DENY PROCESS_TERMINATE/SUSPEND для всех (важно: deny идёт первым в DACL) */
    ea[0].grfAccessPermissions = PROCESS_TERMINATE | PROCESS_SUSPEND_RESUME;
    ea[0].grfAccessMode        = DENY_ACCESS;
    ea[0].grfInheritance       = NO_INHERITANCE;
    ea[0].Trustee.TrusteeForm  = TRUSTEE_IS_SID;
    ea[0].Trustee.TrusteeType  = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea[0].Trustee.ptstrName    = (LPWSTR)everyoneSid;

    /* ALLOW базовые читающие права для всех (чтобы tasklist/диспетчер видели процесс) */
    ea[1].grfAccessPermissions = PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE | READ_CONTROL;
    ea[1].grfAccessMode        = SET_ACCESS;
    ea[1].grfInheritance       = NO_INHERITANCE;
    ea[1].Trustee.TrusteeForm  = TRUSTEE_IS_SID;
    ea[1].Trustee.TrusteeType  = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea[1].Trustee.ptstrName    = (LPWSTR)everyoneSid;

    /* ALLOW всё для SYSTEM */
    ea[2].grfAccessPermissions = PROCESS_ALL_ACCESS;
    ea[2].grfAccessMode        = SET_ACCESS;
    ea[2].grfInheritance       = NO_INHERITANCE;
    ea[2].Trustee.TrusteeForm  = TRUSTEE_IS_SID;
    ea[2].Trustee.TrusteeType  = TRUSTEE_IS_USER;
    ea[2].Trustee.ptstrName    = (LPWSTR)systemSid;

    PACL newDacl = nullptr;
    if (SetEntriesInAclW(3, ea, nullptr, &newDacl) == ERROR_SUCCESS) {
        SetSecurityInfo(GetCurrentProcess(), SE_KERNEL_OBJECT,
                        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                        nullptr, nullptr, newDacl, nullptr);
        LocalFree(newDacl);
    }

    FreeSid(everyoneSid);
    FreeSid(systemSid);
}
