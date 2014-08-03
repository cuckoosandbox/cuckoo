#include <winsock2.h>
#include <stdio.h>
#include <windows.h>

int main(int argc, char **argv){
	printf("This is dl.exe.");

	// make dns request
    gethostbyname("facebook.com");
    
    // create / read registry key
    HKEY hKey;
    DWORD dwFunc;
    LONG  lRet;
    SECURITY_DESCRIPTOR SD;
    SECURITY_ATTRIBUTES SA;
    SA.nLength             = sizeof(SA);
    SA.lpSecurityDescriptor = &SD;
    SA.bInheritHandle      = 0;
    lRet = RegCreateKeyEx(HKEY_LOCAL_MACHINE,
        "Software\\Cuckoo\\DL.exe",
        0,
        (LPTSTR)NULL,
        REG_OPTION_NON_VOLATILE,
        KEY_WRITE,
        &SA,
        &hKey,
        &dwFunc
    );

    if(lRet == ERROR_SUCCESS)
    {
        RegCloseKey(hKey);
        hKey = (HKEY)NULL;
    }    

    // download file



    return 0;

}
