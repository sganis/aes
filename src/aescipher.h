#include <string>
#include <vector>

class AESCipher {
public:
    AESCipher(const std::string& password, bool verbose=false)
        : m_password(password),
          m_verbose(verbose) {}
    virtual ~AESCipher() {}
    std::string encrypt(const std::string &text);
    std::string decrypt(const std::string &enc);

private:
    std::string m_password;
    bool m_verbose;
    std::vector<unsigned char> m_key;    
    unsigned char m_iv[16];
    std::string pad(const std::string &data);
    std::string unpad(const std::string &data);
    void get_key_and_iv(std::vector<unsigned char> &salt);
    std::vector<unsigned char> get_salt();
};
