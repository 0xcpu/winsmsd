#include "winsmsd.h"

#define SystemHandleInformation     0x10
#define ObjectNameInformation       1
#define STATUS_SUCCESS              ((NTSTATUS)0x00000000L)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xc0000004L)



//
// Ref: https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/handle.htm
//
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    ULONG   UniqueProcessId;
    UCHAR   ObjectTypeIndex;
    UCHAR   HandleAttributes;
    USHORT  HandleValue;
    PVOID   Object;
    ULONG   GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG                           NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO  Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

static_assert(sizeof(SYSTEM_HANDLE_INFORMATION) == 0x20, "SYSTEM_HANDLE_TABLE_ENTRY_INFO size is not 0x20 bytes");

//
// Ref: https://github.com/PKRoma/ProcessHacker/blob/245b40d90d5c4f9faf54aa7abffeb6b0dd559413/phnt/include/ntobapi.h#L65
//
typedef struct _OBJECT_NAME_INFORMATION
{
    UNICODE_STRING Name;
} OBJECT_NAME_INFORMATION, * POBJECT_NAME_INFORMATION;

typedef long (*NTDUPLICATEOBJECT)(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, BOOLEAN, ULONG);
typedef NTSTATUS(*NTQUERYSYSTEMINFORMATION)(
    ULONG   SystemInformationClass,
    PVOID   SystemInformation,
    ULONG   SystemInformationLength,
    PULONG  ReturnLength);
typedef NTSTATUS(*NTQUERYOBJECT)(
    HANDLE                   Handle,
    OBJECT_INFORMATION_CLASS ObjectInformationClass,
    PVOID                    ObjectInformation,
    ULONG                    ObjectInformationLength,
    PULONG                   ReturnLength
    );

NTDUPLICATEOBJECT           pNtDuplicateObject;
NTQUERYSYSTEMINFORMATION    pNtQuerySystemInformation;
NTQUERYOBJECT               pNtQueryObject;

BOOL Init(VOID)
{
    WORD    wVersionRequested;
    WSADATA WsaData;
    INT     WsaErr;

    fwprintf(stdout, L"\n=== Init ===\n");

    wVersionRequested = MAKEWORD(2, 2);
    WsaErr = WSAStartup(wVersionRequested, &WsaData);
    if (WsaErr != 0) {
        fwprintf(stderr, L"Failed initializing Winsock: %d\n", WsaErr);

        return FALSE;
    }

    pNtDuplicateObject = (NTDUPLICATEOBJECT)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtDuplicateObject");
    pNtQuerySystemInformation = (NTQUERYSYSTEMINFORMATION)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");
    pNtQueryObject = (NTQUERYOBJECT)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryObject");

    if (pNtDuplicateObject && pNtQuerySystemInformation && pNtQueryObject) {
        return TRUE;
    } else {
        WSACleanup();

        return FALSE;
    }
}

VOID Cleanup(VOID)
{
    fwprintf(stdout, L"\n=== Cleanup ===\n");

    WSACleanup();
}

BOOL IsTargetIPAndPort(HANDLE hSocket, PBYTE TargetIp, USHORT TargetPort)
{
    INT         ret;
    SOCKADDR_IN SockAddr;
    INT         NameLen = sizeof(SOCKADDR_IN);

    ret = getpeername((SOCKET)hSocket, (PSOCKADDR)&SockAddr, &NameLen);
    if (ret != 0) {
        fwprintf(stderr, L"Failed to retrieve address of peer: %d\n", ret);

        return FALSE;
    } else {
        fwprintf(stdout, L"Address: %u.%u.%u.%u Port: %hu\n",
                 SockAddr.sin_addr.S_un.S_un_b.s_b1,
                 SockAddr.sin_addr.S_un.S_un_b.s_b2,
                 SockAddr.sin_addr.S_un.S_un_b.s_b3,
                 SockAddr.sin_addr.S_un.S_un_b.s_b4,
                 ntohs(SockAddr.sin_port));
        //
        // better to check by individual fields
        //
        if (memcmp((PVOID)&SockAddr.sin_addr.S_un.S_un_b, (PVOID)TargetIp, 4) == 0 &&
            ntohs(SockAddr.sin_port) == TargetPort) {
            return TRUE;
        } else {
            return FALSE;
        }
    }
}

SOCKET GetSocket(HANDLE hProcess, PBYTE pIpAddress, USHORT dwPort)
{
    PSYSTEM_HANDLE_INFORMATION  pSysHandleInfo = NULL;
    POBJECT_NAME_INFORMATION    pObjNameInfo = NULL;
    ULONG                       SystemInformationLength = 0;
    ULONG                       ObjectInformationLength = 0;
    ULONG                       ReturnLength;
    HANDLE                      TargetHandle = INVALID_HANDLE_VALUE;
    SOCKET                      TargetSocket = INVALID_SOCKET;
    NTSTATUS                    ntStatus;
    PCWSTR                      pcwDeviceAfd = L"\\Device\\Afd";
    INT                         WsaErr;
    WSAPROTOCOL_INFOW           WsaProtocolInfo = { 0 };

    pSysHandleInfo = (PSYSTEM_HANDLE_INFORMATION)calloc(SystemInformationLength, sizeof(UCHAR));
    if (NULL == pSysHandleInfo) {
        goto ret_inv_handle;
    }
    while (pNtQuerySystemInformation(SystemHandleInformation,
                                     pSysHandleInfo,
                                     SystemInformationLength,
                                     &ReturnLength) == STATUS_INFO_LENGTH_MISMATCH) {
        free(pSysHandleInfo);
        SystemInformationLength = ReturnLength;
        pSysHandleInfo = (PSYSTEM_HANDLE_INFORMATION)calloc(SystemInformationLength, sizeof(UCHAR));
        if (NULL == pSysHandleInfo) {
        ret_inv_handle:
            fwprintf(stderr, L"Failed to allocate buffer for system handles: %08x\n", GetLastError());

            return TargetSocket;
        }
    }
    assert(pSysHandleInfo != NULL);
    fwprintf(stdout, L"Retrieved %u handles\n", pSysHandleInfo->NumberOfHandles);

    for (size_t i = 0; i < pSysHandleInfo->NumberOfHandles; i++) {
        if (pSysHandleInfo->Handles[i].ObjectTypeIndex != 0x24) {
            ntStatus = pNtDuplicateObject(hProcess,
                                          (HANDLE)pSysHandleInfo->Handles[i].HandleValue,
                                          GetCurrentProcess(),
                                          &TargetHandle,
                                          PROCESS_ALL_ACCESS, // ignored
                                          FALSE,
                                          DUPLICATE_SAME_ACCESS);
            if (ntStatus == STATUS_SUCCESS) {
                pObjNameInfo = (POBJECT_NAME_INFORMATION)calloc(ObjectInformationLength, sizeof(UCHAR));
                if (NULL == pObjNameInfo) {
                    goto ret_inv_handle2;
                }
                while (pNtQueryObject(TargetHandle,
                                      (OBJECT_INFORMATION_CLASS)ObjectNameInformation,
                                      pObjNameInfo,
                                      ObjectInformationLength,
                                      &ReturnLength) == STATUS_INFO_LENGTH_MISMATCH) {
                    free(pObjNameInfo);
                    ObjectInformationLength = ReturnLength;
                    pObjNameInfo = (POBJECT_NAME_INFORMATION)calloc(ObjectInformationLength, sizeof(UCHAR));
                    if (NULL == pObjNameInfo) {
                    ret_inv_handle2:
                        fwprintf(stderr, L"Failed to allocate buffer for object name: %08x\n", GetLastError());

                        CloseHandle(TargetHandle);
                        free(pSysHandleInfo);
                        pSysHandleInfo = NULL;

                        return TargetSocket;
                    }
                }

                if ((pObjNameInfo->Name.Length / 2) == wcslen(pcwDeviceAfd)) {
                    if ((wcsncmp(pObjNameInfo->Name.Buffer, pcwDeviceAfd, wcslen(pcwDeviceAfd)) == 0) &&
                        IsTargetIPAndPort(TargetHandle, pIpAddress, dwPort)) {
                        WsaErr = WSADuplicateSocketW((SOCKET)TargetHandle, GetCurrentProcessId(), &WsaProtocolInfo);
                        if (WsaErr != 0) {
                            fwprintf(stderr, L"Failed retrieving WSA protocol info: %d\n", WsaErr);

                            CloseHandle(TargetHandle);
                            free(pObjNameInfo);
                            free(pSysHandleInfo);
                            pSysHandleInfo = NULL;
                            pObjNameInfo = NULL;

                            return TargetSocket;
                        } else {
                            TargetSocket = WSASocket(WsaProtocolInfo.iAddressFamily,
                                                     WsaProtocolInfo.iSocketType,
                                                     WsaProtocolInfo.iProtocol,
                                                     &WsaProtocolInfo,
                                                     0,
                                                     WSA_FLAG_OVERLAPPED);
                            if (TargetSocket != INVALID_SOCKET) {
                                fwprintf(stdout, L"[OK] Socket was duplicated!\n");

                                CloseHandle(TargetHandle);
                                free(pObjNameInfo);
                                free(pSysHandleInfo);
                                pObjNameInfo = NULL;
                                pSysHandleInfo = NULL;

                                return TargetSocket;
                            }
                        }
                    }
                }

                CloseHandle(TargetHandle);
                free(pObjNameInfo);
                pObjNameInfo = NULL;
            }
        }
    }

    free(pSysHandleInfo);

    return TargetSocket;
}

int main(int argc, char** argv)
{
    DWORD   dwPid;
    USHORT  uPort;
    BYTE    IpAddress[4] = { 0 };
    HANDLE  hProc;
    PCHAR   pToken = NULL;
    PCHAR   Ptr;
    SIZE_T  i = 0;

    if (argc < 4) {
        fwprintf(stderr, L"USAGE: %S <PID> <IPv4> <PORT>\n", argv[0]);

        return EXIT_FAILURE;
    }

    if (!Init()) {
        fwprintf(stderr, L"Initialization failed\n");

        return EXIT_FAILURE;
    }

    dwPid = strtoul(argv[1], NULL, 10);
    if (errno == ERANGE && dwPid == ULONG_MAX) {
        fwprintf(stderr, L"Conversion failed: errno = %d\n", errno);

        return EXIT_FAILURE;
    } else if (dwPid == 0) {
        fwprintf(stderr, L"No conversion can be performed\n");

        return EXIT_FAILURE;
    }
    //
    // no error checking
    //
    uPort = (USHORT)strtoul(argv[3], NULL, 10);
    pToken = strtok_s(argv[2], ".", &Ptr);
    while (pToken && i < 4) {
        //
        // no error checking
        //
        IpAddress[i] = (BYTE)strtoul(pToken, NULL, 10);

        pToken = strtok_s(NULL, ".", &Ptr);
        i++;
    }

    hProc = OpenProcess(PROCESS_DUP_HANDLE, FALSE, dwPid);
    if (NULL == hProc) {
        fwprintf(stderr, L"Failed to open process with PID: %u error: %08x\n", dwPid, GetLastError());

        return EXIT_FAILURE;
    }

    BYTE Buff[128] = { 0 };
    SOCKET NewSocket = GetSocket(hProc, IpAddress, uPort);
    if (NewSocket != INVALID_SOCKET) {
        while (recv(NewSocket, Buff, 128, MSG_PEEK) == -1);
        for (size_t i = 0; i < 128; i++) {
            printf("%02X%c", Buff[i], " \n"[(i + 1) % 8 == 0]);
        }

        closesocket(NewSocket);
    }

    Cleanup();

    CloseHandle(hProc);

    return EXIT_SUCCESS;
}
