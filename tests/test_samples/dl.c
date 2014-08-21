
#include <winsock2.h>
#include <stdio.h>
#include <windows.h>
#include <curl/curl.h>
#include <string.h>
#include <ntdef.h>
#include <ddk/ntifs.h>
#include <wininet.h>
#define _countof(x) ((sizeof(x)/sizeof(0[x])) / ((size_t)(!(sizeof(x) % sizeof(0[x])))))

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

// NtQueryKey
typedef NTSTATUS (STDAPICALLTYPE NTQUERYKEY)
(
    IN HANDLE   KeyHandle,
    IN KEY_INFORMATION_CLASS KeyInformationClass,
    OUT PVOID   KeyInformation,
    IN ULONG    KeyInformationLength,
    OUT PULONG  ResultLength
   );
typedef NTQUERYKEY FAR * LPNTQUERYKEY;

// NtEnumerateKey
typedef NTSTATUS (STDAPICALLTYPE NTENUMERATEKEY)
(
    IN HANDLE KeyHandle,
    IN ULONG  Index,
    IN KEY_INFORMATION_CLASS KeyInformationClass,
    OUT PVOID KeyInformation,
    IN ULONG  KeyInformationLength,
    OUT PULONG  ResultLength
   );
typedef NTENUMERATEKEY FAR * LPNTENUMERATEKEY;


// NtDeleteKey
typedef NTSTATUS (STDAPICALLTYPE NTDELETEKEY)
(
  IN HANDLE KeyHandle
);
typedef NTDELETEKEY FAR * LPNTDELETEKEY;


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
    char outfilename[FILENAME_MAX] = "C:downloaded.exe";

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
    LPNTQUERYKEY NtQueryKey;
    LPNTENUMERATEKEY NtEnumerateKey;
    LPNTDELETEKEY NtDeleteKey;
    NTSTATUS m_NtStatus;

    /// Vars for WinINet     
    HINTERNET hOpen = NULL;
    HINTERNET hFile = NULL;
    HANDLE hOut = NULL;
    char* data = NULL;
    DWORD dataSize = 0;
    DWORD dwBytesRead = 0;
    DWORD dwBytesWritten = 0;

	  printf("This is dl.exe.\n");

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


    printf("Loading ntdll\n");
    // create a key via native api
    hinstStub = GetModuleHandle("ntdll.dll");
    RtlInitAnsiString = (LPRTLINITANSISTRING)GetProcAddress(hinstStub, "RtlInitAnsiString");
    RtlAnsiStringToUnicodeString = (LPRTLANSISTRINGTOUNICODESTRING)GetProcAddress(hinstStub, "RtlAnsiStringToUnicodeString");
    NtCreateKey = (LPNTCREATEKEY)GetProcAddress(hinstStub, "NtCreateKey");
    NtClose = (LPNTCLOSE)GetProcAddress(hinstStub, "NtClose");
    NtQueryKey = (LPNTQUERYKEY)GetProcAddress(hinstStub, "NtQueryKey");
    NtEnumerateKey = (LPNTENUMERATEKEY)GetProcAddress(hinstStub, "NtEnumerateKey");
    NtDeleteKey = (LPNTDELETEKEY)GetProcAddress(hinstStub, "NtDeleteKey");

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
    printf("Calling NtCreateKey\n");
    m_NtStatus = NtCreateKey(&hKey2,
                           KEY_ALL_ACCESS,
                           &ObjectAttributes,
                           0,
                           NULL,
                           REG_OPTION_NON_VOLATILE,
                           &m_dwDisposition);

    if (!NT_SUCCESS(m_NtStatus)) {
      printf("failed: %d!\n",m_NtStatus);
    }
    else {

      printf("EnumerateKey\n");
      WCHAR buffer[256];
      KEY_FULL_INFORMATION *info = (KEY_FULL_INFORMATION *)buffer;
      DWORD dwResultLength;
      m_NtStatus = NtEnumerateKey(&hKey2,
                           0,
                           KeyFullInformation,
                           info,
                           sizeof(buffer),
                           &dwResultLength);

      printf("Enumerate Result: %s\n",buffer);
      printf("Deleting the key again.\n");
      m_NtStatus = NtDeleteKey(hKey2);
      if(!NT_SUCCESS(m_NtStatus)) {
        printf("Failed to delete Key\n");
      }
      NtClose(hKey2);
    }

    printf("Calling NtQueryKey\n");
    WCHAR buffer[256];
    KEY_FULL_INFORMATION *info = (KEY_FULL_INFORMATION *)buffer;
    DWORD dwResultLength;
    m_NtStatus = NtQueryKey(hKey,
                            KeyFullInformation,
                            buffer,
                            sizeof(buffer),
                            &dwResultLength);
    printf("Query: %s\n",buffer);

    // make dns request
    printf("Resolving host\n");

    gethostbyname("facebook.com");


    printf("Downloading file\n");
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


    // WinINnet test: InternetOpen/ReadFile 
    hOpen = InternetOpenW(L"MyAgent", NULL, NULL, NULL, NULL);
    if(!hOpen) return NULL;

    hFile = InternetOpenUrlW(hOpen, L"http://192.168.56.1:8089/tests/test_samples/dl.c", NULL, NULL, INTERNET_FLAG_RELOAD | INTERNET_FLAG_DONT_CACHE, NULL);
    do {
      char buffer[5000];
      InternetReadFile(hFile, (LPVOID)buffer, _countof(buffer), &dwBytesRead);
      char *tempData = new char[dataSize + dwBytesRead];
      memcpy(tempData, data, dataSize);
      memcpy(tempData + dataSize, buffer, dwBytesRead);
      delete[] data;
      data = tempData;
      dataSize += dwBytesRead;
    } while (dwBytesRead);
    InternetCloseHandle(hFile);
    InternetCloseHandle(hOpen);

    Sleep(1000);
    printf("Finished\n");
    return 0;

}
