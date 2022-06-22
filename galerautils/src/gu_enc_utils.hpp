#ifndef __GU_ENCRYPTION__
#define __GU_ENCRYPTION__

#include <string>
#include <functional>

namespace gu {
class UUID;
class Config;

#define ptr2ull(ptr) ((unsigned long long)ptr)

std::string encode64(const std::string& binary);
std::string decode64(const std::string& base64);
std::string generateRandomKey();
std::string EncryptKey(const std::string &keyToBeEncrypted, const std::string &key);
std::string DecryptKey(const std::string &keyToBeDecrypted, const std::string &key);
std::string CreateMasterKeyName(UUID& uuid, int keyId);

class MasterKeyProvider {
public:
    MasterKeyProvider(std::function<std::string()> getCurrentKeyCb);
    void RegisterKeyRotationRequestObserver(std::function<bool(const std::string&)> fn);
    bool NotifyKeyRotationObserver(const std::string& key);
    std::string GetCurrentKey();

private:
    std::function<bool(const std::string&)> keyRotationObserver_;
    std::function<std::string()> getCurrentKeyCb_;
};

}
#endif  /* __GU_ENCRYPTION__ */