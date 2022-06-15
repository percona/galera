#ifndef __GU_ENCRYPTION__
#define __GU_ENCRYPTION__

#include <string>

namespace gu {

std::string encode64(const std::string& binary);
std::string decode64(const std::string& base64);
std::string generateRandomKey();

}
#endif  /* __GU_ENCRYPTION__ */