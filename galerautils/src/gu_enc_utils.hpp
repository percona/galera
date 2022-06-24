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
    MasterKeyProvider(std::function<std::string(const std::string&)> getKeyCb,
      std::function<bool(const std::string&)> createKeyCb);
    void RegisterKeyRotationRequestObserver(std::function<bool()> fn);
    bool NotifyKeyRotationObserver();
    std::string GetKey(const std::string& keyId);
    bool CreateKey(const std::string& keyId);

private:
    std::function<bool()> keyRotationObserver_;
    std::function<std::string(const std::string&)> getKeyCb_;
    std::function<bool(const std::string&)> createKeyCb_;
};

}
#endif  /* __GU_ENCRYPTION__ */