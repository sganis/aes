#include <string.h>
#include "aescipher.h"
#include "picosha2.h"
#include "plusaes.h"
#include "base64.h"

const char* error_string[] = {
    "Ok",
    "Invalid Data Size",
    "Invalid Key Size",
    "Invalid Buffer Size",
    "Invalid Key",
};

std::vector<unsigned char> AESCipher::get_salt()
{
    std::vector<unsigned char> salt;
    srand (time(NULL));
    for(int i=0; i < 8; i++)
        salt.push_back((unsigned char) rand());
    return salt;
}
void AESCipher::get_key_and_iv(std::vector<unsigned char>& salt)
{
    std::vector<unsigned char> hash(32);
    std::string salt_str(salt.begin(), salt.end());
    std::string input = m_password + salt_str;
    picosha2::hash256(input.begin(), input.end(), hash.begin(), hash.end());
    std::string output = std::string(hash.begin(), hash.end());
    input = output + m_password + salt_str;
    picosha2::hash256(input.begin(), input.end(), hash.begin(), hash.end());
    output += std::string(hash.begin(), hash.end());

    m_key = std::vector<unsigned char>(output.begin(), output.begin()+32);
    std::vector<unsigned char> iv(output.begin()+32, output.begin()+48);
    for(int i=0; i < 16; i++)
        m_iv[i] = iv[i];
}

std::string AESCipher::pad(const std::string& data)
{
    size_t len = data.size() + (16 - data.size() % 16);
    unsigned char padchar = 16 - data.size() % 16;
    std::string padded = data;
    for(int i=data.size(); i < len; i++)
        padded.push_back(padchar);
    return padded;
}

std::string AESCipher::unpad(const std::string& data)
{
    int paddchar = data.back();
    if(paddchar < 16) {
        std::string unpadded(data.begin(),  data.end() - paddchar);
        return unpadded;
    } else {
        return data;
    }
}

std::string AESCipher::encrypt(const std::string & data)
{
    std::vector<unsigned char> salt = get_salt();
    get_key_and_iv(salt);
    std::string padded_data = pad(data);
    std::vector<unsigned char> encrypted(padded_data.size());

    plusaes::Error e = plusaes::encrypt_cbc(
                (unsigned char*)padded_data.data(),
                (unsigned long)padded_data.size(),
                &m_key[0], 32, &m_iv,
                &encrypted[0], (unsigned long)encrypted.size(), false);

    if(e == plusaes::kErrorOk) {
        std::string encstr(encrypted.begin(), encrypted.end());
        std::string salt_str(salt.begin(), salt.end());
        std::string result = std::string("Salted__") + salt_str + encstr;
        std::string b64 =base64_encode((unsigned char*)(result.c_str()), result.length());
        if(m_verbose) {
            printf("text = %s\n", data.c_str());
            printf("salt = %s\n", picosha2::bytes_to_hex_string(salt.begin(), salt.end()).c_str());
            printf("key  = %s\n", picosha2::bytes_to_hex_string(m_key.begin(), m_key.end()).c_str());
            printf("iv   = %s\n", picosha2::bytes_to_hex_string(salt.begin(), salt.end()).c_str());
            printf("enc  = %s\n", b64.c_str());
        }
        return b64;
    } else {
        if(e>0 && e < 5)
            fprintf(stderr, "%s\n", error_string[e]);
        return std::string();
    }
}

std::string AESCipher::decrypt(const std::string & base64str)
{
    std::string data = base64_decode(base64str);
    if(data.length() < 16) {
        fprintf(stderr, "%s\n", error_string[1]);
        return std::string();
    }

    std::vector<unsigned char> encrypted(data.begin()+16, data.end());
    std::vector<unsigned char> salt = std::vector<unsigned char>(data.begin()+8, data.begin()+16);
    get_key_and_iv(salt);

    std::vector<unsigned char> decrypted(encrypted.size());

    plusaes::Error e = plusaes::decrypt_cbc(
                &encrypted[0], (unsigned long)encrypted.size(),
                &m_key[0], 32, &m_iv,
                &decrypted[0], (unsigned long)decrypted.size(), 0);

    if(e == plusaes::kErrorOk) {
        std::string padded(decrypted.begin(), decrypted.end());
        std::string result = unpad(padded);
        if(m_verbose) {
            printf("enc  = %s\n", base64str.c_str());
            printf("salt = %s\n", picosha2::bytes_to_hex_string(salt.begin(), salt.end()).c_str());
            printf("key  = %s\n", picosha2::bytes_to_hex_string(m_key.begin(), m_key.end()).c_str());
            printf("iv   = %s\n", picosha2::bytes_to_hex_string(salt.begin(), salt.end()).c_str());
            printf("text = %s\n", result.c_str());
        }
        return result;
    } else {
        if(e>0 && e < 5)
            fprintf(stderr, "%s\n", error_string[e]);
        return std::string();
    }
}

