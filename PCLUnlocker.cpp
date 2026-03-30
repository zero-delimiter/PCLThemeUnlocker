#include <windows.h>
#include <wincrypt.h>
#include <iostream>
#include <string>
#include <vector>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <stdint.h>
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")

static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static std::string base64Encode(const std::vector<uint8_t>& data) {
    std::string out;
    int val = 0, valb = -6;
    for (uint8_t c : data) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) { out += B64[(val >> valb) & 0x3F]; valb -= 6; }
    }
    if (valb > -6) out += B64[((val << 8) >> (valb + 8)) & 0x3F];
    while (out.size() % 4) out += '=';
    return out;
}

static std::vector<uint8_t> desCbcEncrypt(const std::vector<uint8_t>& plain, const uint8_t key[8], const uint8_t iv[8]) {
    HCRYPTPROV hProv = 0;
    HCRYPTKEY  hKey = 0;

    if (!CryptAcquireContextA(&hProv, NULL, MS_ENHANCED_PROV_A,
        PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        return {};
    }

    struct {
        BLOBHEADER hdr;
        DWORD      keySize;
        BYTE       keyData[8];
    } keyBlob;

    keyBlob.hdr.bType = PLAINTEXTKEYBLOB;
    keyBlob.hdr.bVersion = CUR_BLOB_VERSION;
    keyBlob.hdr.reserved = 0;
    keyBlob.hdr.aiKeyAlg = CALG_DES;
    keyBlob.keySize = 8;
    memcpy(keyBlob.keyData, key, 8);

    if (!CryptImportKey(hProv, (BYTE*)&keyBlob, sizeof(keyBlob), 0, CRYPT_EXPORTABLE, &hKey)) {
        CryptReleaseContext(hProv, 0);
        return {};
    }

    DWORD mode = CRYPT_MODE_CBC;
    CryptSetKeyParam(hKey, KP_MODE, (BYTE*)&mode, 0);
    CryptSetKeyParam(hKey, KP_IV, (BYTE*)iv, 0);

    DWORD dataLen = (DWORD)plain.size();
    DWORD bufLen = (DWORD)((dataLen / 8 + 1) * 8);
    std::vector<uint8_t> buf(plain);
    buf.resize(bufLen);

    if (!CryptEncrypt(hKey, 0, TRUE, 0, buf.data(), &dataLen, bufLen)) {
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        return {};
    }
    buf.resize(dataLen);

    CryptDestroyKey(hKey);
    CryptReleaseContext(hProv, 0);
    return buf;
}

static uint64_t getHash(const char* input) {
    uint64_t num = 5381ULL;
    for (const char* p = input; *p; p++)
        num = (num << 5) ^ num ^ (unsigned char)(*p);
    return num ^ 12218072394304324399ULL;
}

static std::string getSecretKey(const std::string& key) {
    if (key.empty()) return "@;$ Abv2";
    uint64_t hashVal = getHash(key.c_str());
    char buf[21];
    snprintf(buf, sizeof(buf), "%llu", (unsigned long long)hashVal);
    std::string s(buf);
    if (s.size() > 8) return s.substr(0, 8);
    std::string padded = s;
    while (padded.size() < 8) padded += 'X';
    return padded.substr(s.size()) + s;
}

static std::string secretEncrypt(const std::string& plainText, const std::string& key) {
    std::string sk = getSecretKey(key);

    uint8_t keyBytes[8] = { 0 };
    size_t copyLen = sk.size() < 8 ? sk.size() : 8;
    memcpy(keyBytes, sk.c_str(), copyLen);

    uint8_t ivBytes[8] = { 0 };
    memcpy(ivBytes, "95168702", 8);

    std::vector<uint8_t> plain(plainText.begin(), plainText.end());
    std::vector<uint8_t> enc = desCbcEncrypt(plain, keyBytes, ivBytes);
    return base64Encode(enc);
}

int main() {
    auto queryRegistryValue = [](HKEY hKeyRoot, const char* subKey, const char* valueName,
        char* outValue, DWORD outSize) -> int {
            HKEY hKey;
            DWORD type = REG_SZ;
            if (RegOpenKeyExA(hKeyRoot, subKey, 0, KEY_READ, &hKey) != ERROR_SUCCESS) return 0;
            if (RegQueryValueExA(hKey, valueName, NULL, &type, (LPBYTE)outValue, &outSize) != ERROR_SUCCESS) {
                RegCloseKey(hKey); return 0;
            }
            RegCloseKey(hKey);
            return 1;
        };

    auto formatUniqueAddress = [](const char* hash, char* formatted) {
        snprintf(formatted, 20, "%.*s-%.*s-%.*s-%.*s",
            4, hash + 4, 4, hash + 12, 4, hash + 0, 4, hash + 8);
        };

    char str[256] = { 0 };
    char text[256] = { 0 };

    if (!queryRegistryValue(HKEY_LOCAL_MACHINE,
        "SYSTEM\\HardwareConfig", "LastConfig", str, sizeof(str))) {
        std::cerr << "Error: Unable to read LastConfig" << std::endl; return 1;
    }
    if (!queryRegistryValue(HKEY_CURRENT_USER,
        "Software\\PCL", "Identify", text, sizeof(text))) {
        std::cerr << "Error: Unable to read Identify" << std::endl; return 1;
    }

    for (char* p = str; *p; p++) *p = (char)toupper((unsigned char)*p);

    char trimmedStr[256] = { 0 };
    for (size_t i = 0, j = 0; i < strlen(str); i++)
        if (str[i] != '{' && str[i] != '}') trimmedStr[j++] = str[i];

    char combined[512] = { 0 };
    snprintf(combined, sizeof(combined), "%s%s", trimmedStr, text);

    uint64_t hashValue = getHash(combined);

    char hashHex[17] = { 0 };
    uint64_t tmp = hashValue;
    for (int i = 15; i >= 0; i--) {
        hashHex[i] = "0123456789ABCDEF"[tmp & 0xF];
        tmp >>= 4;
    }

    char paddedHash[17];
    memset(paddedHash, '7', 16);
    paddedHash[16] = '\0';
    size_t hexLen = strlen(hashHex);

    if (hexLen <= 16) 
        memcpy(paddedHash + (16 - hexLen), hashHex, hexLen);
    else              
        memcpy(paddedHash, hashHex + (hexLen - 16), 16);

    char formattedAddress[20];
    formatUniqueAddress(paddedHash, formattedAddress);

    std::string hardwareId(formattedAddress);
    std::cout << "识别码: " << hardwareId << std::endl;

    std::string encValue = secretEncrypt("0|1|2|3|4|5|6|7|8|9|10|11|12|13|14", "PCL" + hardwareId);
    std::cout << "解锁密钥: " << encValue << std::endl;

    HKEY hKey;
    if (RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\PCL", 0, NULL,
        REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExA(hKey, "UiLauncherThemeHide2", 0, REG_SZ, (const BYTE*)encValue.c_str(), (DWORD)(encValue.size() + 1));
        RegCloseKey(hKey);
        std::cout << "主题解锁完毕。" << std::endl;
    }
    else {
        std::cerr << "主题解锁失败！" << std::endl; return 1;
    }

    system("pause");

    return 0;
}