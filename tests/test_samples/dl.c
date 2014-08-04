#include <winsock2.h>
#include <stdio.h>
#include <windows.h>
#include <curl/curl.h>
#include <string.h>

size_t write_data(void *ptr, size_t size, size_t nmemb, FILE *stream) {
    size_t written = fwrite(ptr, size, nmemb, stream);
    return written;
}


int main(int argc, char **argv){
    HKEY hKey;
    DWORD dwFunc;
    LONG  lRet;
    SECURITY_DESCRIPTOR SD;
    SECURITY_ATTRIBUTES SA;

    CURL *curl;
    FILE *fp;
    char *url = "http://192.168.56.1:8089/tests/test_samples/dl.exe";
    char outfilename[FILENAME_MAX] = "C:\\downloaded.exe";


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

    return 0;

}
