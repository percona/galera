#ifndef __GU_ENCRYPTION__
#define __GU_ENCRYPTION__

#include <string>

namespace gu {
class UUID;

#define ptr2ull(ptr) ((unsigned long long)ptr)

std::string encode64(const std::string& binary);
std::string decode64(const std::string& base64);
std::string generateRandomKey();
std::string EncryptKey(const std::string &keyToBeEncrypted, const std::string &key);
std::string DecryptKey(const std::string &keyToBeDecrypted, const std::string &key);
std::string CreateMasterKeyName(UUID& uuid, int keyId);
}
#endif  /* __GU_ENCRYPTION__ */