#include <iostream>
#include <string>
#include <filesystem>
#include <vector>
#include <windows.h>
#include <wincrypt.h>

#pragma comment(lib, "crypt32.lib")

bool isUnsigned(const std::wstring& filepath) {
    DWORD dwEncoding = 0;
    DWORD dwContentType = 0;
    DWORD dwFormatType = 0;
    PCERT_INFO pCertInfo = NULL;
    DWORD cbCertInfo = 0;
    HCERTSTORE hStore = NULL;
    HCRYPTMSG hMsg = NULL;
    BOOL fResult = FALSE;
    DWORD dwFlags = 0;

    // Open the file and get a handle to it
    HANDLE hFile = CreateFile(filepath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "Error opening file: " << filepath << std::endl;
        return true; // Assume unsigned if can't open file
    }

    // Determine the file size
    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        std::cerr << "Error getting file size for file: " << filepath << std::endl;
        CloseHandle(hFile);
        return true; // Assume unsigned if can't get file size
    }

    // Map the file into memory
    HANDLE hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (hMapping == NULL) {
        std::cerr << "Error mapping file: " << filepath << std::endl;
        CloseHandle(hFile);
        return true; // Assume unsigned if can't map file
    }

    LPVOID lpvFile = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (lpvFile == NULL) {
        std::cerr << "Error mapping view of file: " << filepath << std::endl;
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return true; // Assume unsigned if can't map view of file
    }

    // Get the certificate from the file
    if (CryptQueryObject(CERT_QUERY_OBJECT_FILE, filepath.c_str(), CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, CERT_QUERY_FORMAT_FLAG_BINARY, 0, &dwEncoding, &dwContentType, &dwFormatType, &hStore, &hMsg, NULL) == FALSE) {
        std::cerr << "Error querying certificate for file: " << filepath << std::endl;
        fResult = true; // Assume unsigned if can't query certificate
        goto cleanup;
    }

    // Get the certificate information
    if (CryptMsgGetParam(hMsg, CMSG_SIGNER_CERT_INFO_PARAM, 0, NULL, &cbCertInfo) == FALSE) {
        std::cerr << "Error getting certificate info size for file: " << filepath << std::endl;
        fResult = true; // Assume unsigned if can't get certificate info size
        goto cleanup;
    }

    pCertInfo = (PCERT_INFO)LocalAlloc(LPTR, cbCertInfo);
    if (pCertInfo == NULL) {
        std::cerr << "Error allocating memory for certificate info for file: " << filepath << std::endl;
        fResult = true; // Assume unsigned if can't allocate memory for certificate info
        goto cleanup;
    }

    if (CryptMsgGetParam(hMsg, CMSG_SIGNER_CERT_INFO
