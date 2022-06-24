#include "gu_enc_utils.hpp"
#include "gu_logger.hpp"
#include "gu_uuid.hpp"
#include "gu_assert.hpp"
#include "gu_config.hpp"
#include "enc_stream_cipher.h"

#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/algorithm/string.hpp>
#include <openssl/rand.h>
#include <openssl/err.h>

// Base64 inspired by
// https://stackoverflow.com/questions/7053538/how-do-i-encode-a-string-to-base64-using-only-boost
namespace gu {

std::string encode64(const std::string& binary)
{
    using namespace boost::archive::iterators;
    using It = base64_from_binary<transform_width<std::string::const_iterator, 6, 8>>;
    auto base64 = std::string(It(binary.begin()), It(binary.end()));
    // Add padding.
    return base64.append((3 - binary.size() % 3) % 3, '=');
}

std::string decode64(const std::string& base64)
{
    using namespace boost::archive::iterators;
    using It = transform_width<binary_from_base64<std::string::const_iterator>, 8, 6>;
    auto binary = std::string(It(base64.begin()), It(base64.end()));
    // Remove padding.
    auto length = base64.size();
    if(binary.size() > 2 && base64[length - 1] == '=' && base64[length - 2] == '=')
    {
        binary.erase(binary.end() - 2, binary.end());
    }
    else if(binary.size() > 1 && base64[length - 1] == '=')
    {
        binary.erase(binary.end() - 1, binary.end());
    }
    return binary;
}

std::string generateRandomKey() {
    char buf[Aes_ctr::FILE_KEY_LENGTH];
    int rc = RAND_bytes(reinterpret_cast<unsigned char*>(buf), Aes_ctr::FILE_KEY_LENGTH);
    if (!rc) {
      ERR_clear_error();
      // fall back to old good rand...
      log_error << "Failed to generate random key using SSL.";
      for (size_t i = 0; i < Aes_ctr::FILE_KEY_LENGTH; ++i) {
        buf[i] = rand() % 255;
      }
    }
    return std::string(buf, Aes_ctr::FILE_KEY_LENGTH);
}

static unsigned char iv[gu::Aes_ctr_decryptor::AES_BLOCK_SIZE] = {0};
std::string EncryptKey(const std::string &keyToBeEncrypted, const std::string &key)
{
    assert(keyToBeEncrypted.length() == Aes_ctr::FILE_KEY_LENGTH);
    assert(key.length() == Aes_ctr::FILE_KEY_LENGTH);

    const unsigned char* keyPtr = reinterpret_cast<const unsigned char*>(key.c_str());
    const unsigned char* keyToBeEncryptedPtr = reinterpret_cast<const unsigned char*>(keyToBeEncrypted.c_str());
    char resultBuf[gu::Aes_ctr::FILE_KEY_LENGTH];
    unsigned char* resultBufPtr = reinterpret_cast<unsigned char*>(resultBuf);

    Aes_ctr_encryptor encryptor;
    encryptor.open(keyPtr, iv);
    encryptor.encrypt(resultBufPtr, keyToBeEncryptedPtr, keyToBeEncrypted.length());
    encryptor.close();

    return std::string(resultBuf, gu::Aes_ctr::FILE_KEY_LENGTH);
}

std::string DecryptKey(const std::string &keyToBeDecrypted, const std::string &key)
{
    assert(keyToBeDecrypted.length() == gu::Aes_ctr::FILE_KEY_LENGTH);
    assert(key.length() == gu::Aes_ctr::FILE_KEY_LENGTH);

    const unsigned char* keyPtr = reinterpret_cast<const unsigned char*>(key.c_str());
    const unsigned char* keyToBeDecryptedPtr = reinterpret_cast<const unsigned char*>(keyToBeDecrypted.c_str());
    char resultBuf[gu::Aes_ctr::FILE_KEY_LENGTH];
    unsigned char* resultBufPtr = reinterpret_cast<unsigned char*>(resultBuf);

    Aes_ctr_decryptor decryptor;
    decryptor.open(keyPtr, iv);
    decryptor.decrypt(resultBufPtr, keyToBeDecryptedPtr, keyToBeDecrypted.length());
    decryptor.close();
    return std::string(resultBuf, gu::Aes_ctr_decryptor::FILE_KEY_LENGTH);
}

std::string CreateMasterKeyName(UUID& uuid, int keyId) {
    static const std::string MASTER_KEY_PREFIX = "GaleraKey-";
    static const std::string MASTER_KEY_SEPARATOR = "-";
    std::ostringstream os;
    os << uuid;

    return MASTER_KEY_PREFIX + os.str() + MASTER_KEY_SEPARATOR +
      std::to_string(keyId);
}


MasterKeyProvider::MasterKeyProvider(std::function<std::string(const std::string&)> getKeyCb,
  std::function<bool(const std::string&)> createKeyCb)
: keyRotationObserver_([](){return true;})
, getKeyCb_(getKeyCb)
, createKeyCb_(createKeyCb) {
}

void MasterKeyProvider::RegisterKeyRotationRequestObserver(std::function<bool()> fn) {
    keyRotationObserver_ = fn;
}

bool MasterKeyProvider::NotifyKeyRotationObserver() {
    return keyRotationObserver_();
}

std::string MasterKeyProvider::GetKey(const std::string& keyId) {
    return getKeyCb_(keyId);
}

bool MasterKeyProvider::CreateKey(const std::string& keyId) {
    return createKeyCb_(keyId);
}


}  // namespace