#include "gu_encryption.hpp"
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/algorithm/string.hpp>

// Inspired by
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
    static int keyLength = 32;
    return "01234567890123456789012345678901";
}

}  // namespace