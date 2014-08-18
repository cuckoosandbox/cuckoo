#include <winsock2.h>
#include <stdio.h>
#include <windows.h>
#include <curl/curl.h>
#include <string.h>
#include <ntdef.h>

size_t write_data(void *ptr, size_t size, size_t nmemb, FILE *stream) {
    size_t written = fwrite(ptr, size, nmemb, stream);
    return written;
}

// RtlInitAnsiString
typedef NTSTATUS (STDAPICALLTYPE RTLINITANSISTRING)
(
  IN OUT PANSI_STRING DestinationString,
  IN LPCSTR SourceString
);
typedef RTLINITANSISTRING FAR * LPRTLINITANSISTRING;

// RtlAnsiStringToUnicodeString
typedef NTSTATUS (STDAPICALLTYPE RTLANSISTRINGTOUNICODESTRING)
(
  IN OUT PUNICODE_STRING DestinationString,
  IN PANSI_STRING SourceString,
  IN BOOLEAN AllocateDestinationString
);
typedef RTLANSISTRINGTOUNICODESTRING FAR * LPRTLANSISTRINGTOUNICODESTRING;
// NtCreateKey
typedef NTSTATUS (STDAPICALLTYPE NTCREATEKEY)
(
  IN HANDLE KeyHandle,
  IN ULONG DesiredAccess,
  IN POBJECT_ATTRIBUTES ObjectAttributes,
  IN ULONG TitleIndex,
  IN PUNICODE_STRING Class,
  IN ULONG CreateOptions,
  OUT PULONG Disposition
);
typedef NTCREATEKEY FAR * LPNTCREATEKEY;

// NtClose
typedef NTSTATUS (STDAPICALLTYPE NTCLOSE)
(
  IN HANDLE KeyHandle
);
typedef NTCLOSE FAR * LPNTCLOSE;


int main(int argc, char **argv){
    // registry variables
    HKEY hKey;
    DWORD dwFunc;
    LONG  lRet;
    SECURITY_DESCRIPTOR SD;
    SECURITY_ATTRIBUTES SA;

    // curl variables
    CURL *curl;
    FILE *fp;
    char *url = "http://192.168.56.1:8089/tests/test_samples/dl.exe";
    char outfilename[FILENAME_MAX] = "C:\\downloaded.exe";

    // Vars for native api registry access
    HINSTANCE hinstStub;
    ANSI_STRING asName;
    UNICODE_STRING usName;
    LPNTCREATEKEY NtCreateKey;
    LPNTCLOSE NtClose;
    LPRTLINITANSISTRING RtlInitAnsiString;
    LPRTLANSISTRINGTOUNICODESTRING RtlAnsiStringToUnicodeString;
    HANDLE hKey2 = NULL;
    DWORD m_dwDisposition;


	printf("This is dl.exe.");

	// make dns request
    gethostbyname("facebook.com");
    
    // create / read registry key
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
    curl = curl_easy_init();
    if (curl) {
        fp = fopen(outfilename,"wb");
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        fclose(fp);
    }

    // create a key via native api
    hinstStub = GetModuleHandle("ntdll.dll");
    RtlInitAnsiString = (LPRTLINITANSISTRING)GetProcAddress(hinstStub, "RtlInitAnsiString");
    RtlAnsiStringToUnicodeString = (LPRTLANSISTRINGTOUNICODESTRING)GetProcAddress(hinstStub, "RtlAnsiStringToUnicodeString");
    NtCreateKey = (LPNTCREATEKEY)GetProcAddress(hinstStub, "NtCreateKey");
    if (!NtCreateKey) {
      return FALSE;
    }
    NtClose = (LPNTCLOSE)GetProcAddress(hinstStub, "NtClose");

    // Ansi2Unicode
    RtlZeroMemory(&asName,sizeof(asName));
    RtlInitAnsiString(&asName,"\\Registry\\Machine\\Software\\CuckooTest");
    RtlZeroMemory(&usName,sizeof(usName));
    RtlAnsiStringToUnicodeString(&usName,&asName,TRUE);

    OBJECT_ATTRIBUTES ObjectAttributes;
    InitializeObjectAttributes(&ObjectAttributes,
                             &usName,
                             OBJ_CASE_INSENSITIVE,
                             NULL,NULL);

    // create key
    NTSTATUS m_NtStatus = NtCreateKey(&hKey2,
                           KEY_ALL_ACCESS,
                           &ObjectAttributes,
                           0,
                           NULL,
                           REG_OPTION_NON_VOLATILE,
                           &m_dwDisposition);

    if (!NT_SUCCESS(m_NtStatus)) {
      printf("failed: %d!\n",m_NtStatus);
      return FALSE;
    }
    else {
      NtClose(hKey2);
    }


    return 0;

}
