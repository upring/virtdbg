
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>


void PrintError()
{
    DWORD dw;
    LPVOID lpMsg;
    dw = GetLastError();

    FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                   NULL,
                   dw,
                   MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US),
                   (char *) &lpMsg,
                   0,
                   NULL);

    printf("error 0x%08x:%s\n", dw, (char*)lpMsg);
}


int _cdecl main(int argc, char **argv)
{
    HANDLE hSCManager;
    HANDLE hService;
    SERVICE_STATUS ss;
    BOOL bStatus;
    char buffer[4096];

    if (argc != 2)
    {
        printf("Usage: %s <driver.sys>\n", argv[0]);
        return 0;
    }

    bStatus = GetFullPathNameA(argv[1], 4096, buffer, NULL);

    if (bStatus == 0)
    {
        PrintError();
        return -1;
    }

    hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);

    if (hSCManager == NULL)
    {
        printf("Can't open SCManager\n");
        PrintError();
        return -1;
    }
    
    printf("Loading driver ...\n");

    printf("Creating service ...\n");

    hService = CreateServiceA(hSCManager, "Virtdbg", 
                             "VirtDbg driver", 
                              SERVICE_START | DELETE | SERVICE_STOP, 
                              SERVICE_KERNEL_DRIVER,
                              SERVICE_DEMAND_START, 
                              SERVICE_ERROR_NORMAL, 
                              buffer, 
                              NULL, NULL, NULL, NULL, NULL);
    
    if (hService == NULL)
    {
        printf("Can't create service, maybe service already created\n");
        PrintError();
        printf("Opening service...\n");

        hService = OpenServiceA(hSCManager, "Virtdbg", 
                       SERVICE_START | DELETE | SERVICE_STOP);
        if (hService == NULL)
        {
            printf("Can't open service\n");
            PrintError();
            goto err;
        }
    }
    
    printf("Starting service\n");

    bStatus = StartService(hService, 0, NULL);
    
    if (bStatus == 0)
    {
        printf("Can't start service\n");
        PrintError();
        goto err;
    }

    printf("Press a key to close service\n");
    getchar();
            
    bStatus = ControlService(hService, SERVICE_CONTROL_STOP, &ss);

    if (bStatus == 0)
    {
        printf("Can't stop service\n");
        PrintError();
        goto err;
    }

err:
    DeleteService(hService);
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    
    return 0;
}
