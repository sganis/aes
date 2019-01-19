#include <string.h>
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

void _generate_iv(unsigned char (* iv)[16])
{
    srand (time(NULL));
    for(int i=0; i < 16; i++)
        (*iv)[i] = (unsigned char) rand();
}
std::string _pad(const std::string& data)
{
    size_t len = data.size() + (16 - data.size() % 16);
    unsigned char padchar = 16 - data.size() % 16;
    std::string padded = data;
    for(int i=data.size(); i < len; i++)
        padded.push_back(padchar);
    return padded;
}
std::string _unpad(const std::string& data)
{
    int paddchar = data.back();
    if(paddchar < 16) {
        std::string unpadded(data.begin(),  data.end() - paddchar);
        return unpadded;
    } else {
        return data;
    }
}
std::string encrypt(const std::string & data, const std::string& password)
{
    std::vector<unsigned char> key(picosha2::k_digest_size);
    picosha2::hash256(password.begin(), password.end(), key.begin(), key.end());
    unsigned char iv[16];
    _generate_iv(&iv);
    std::string padded_data = _pad(data);
    std::vector<unsigned char> encrypted(padded_data.size());

    plusaes::Error e = plusaes::encrypt_cbc(
                (unsigned char*)padded_data.data(),
                (unsigned long)padded_data.size(),
                &key[0], (int)key.size(), &iv,
                &encrypted[0], (unsigned long)encrypted.size(), false);

    if(e == plusaes::kErrorOk) {
        std::string ivstr( iv, iv + 16 / sizeof iv[0] );
        std::string encstr(encrypted.begin(), encrypted.end());
        std::string result = ivstr + encstr;
        return base64_encode((unsigned char*)(result.c_str()), result.length());
    } else {
        if(e>0 && e < 5)
            fprintf(stderr, "%s\n", error_string[e]);
        return std::string();
    }

}

std::string decrypt(const std::string & base64str,  const std::string & password)
{
    std::string data = base64_decode(base64str);
    if(data.length() < 16) {
        fprintf(stderr, "%s\n", error_string[1]);
        return std::string();
    }
    unsigned char iv[16];
    for(int i=0; i < 16; i++)
        iv[i]=data[i];

    std::vector<unsigned char> key(picosha2::k_digest_size);
    picosha2::hash256(password.begin(), password.end(), key.begin(), key.end());

    std::vector<unsigned char> encrypted(data.begin()+16, data.end());
    std::vector<unsigned char> decrypted(encrypted.size());

    //unsigned long padded_size = 0;
    plusaes::Error e = plusaes::decrypt_cbc(
                &encrypted[0], (unsigned long)encrypted.size(),
                &key[0], (int)key.size(), &iv,
                &decrypted[0], (unsigned long)decrypted.size(),
                0);

    if(e == plusaes::kErrorOk) {
        std::string padded(decrypted.begin(), decrypted.end());
        std::string result = _unpad(padded);
        return result;
    } else {
        if(e>0 && e < 5)
            fprintf(stderr, "%s\n", error_string[e]);
        return std::string();
    }
}

int main(int argc, char *argv[])
{
    std::string password = "password";
    std::string text = "hello world";
    std::vector<unsigned char> hash(picosha2::k_digest_size);
    picosha2::hash256(password.begin(), password.end(), hash.begin(), hash.end());
    std::string hex_pass = picosha2::bytes_to_hex_string(hash.begin(), hash.end());
    printf("hexkey: %s\n", hex_pass.c_str());

    std::string cipher = encrypt(text, password);
    printf("text  : %s\n", text.c_str());
    printf("cipher: %s\n", cipher.c_str());
    text = decrypt(cipher, password);
    printf("text  : %s\n", text.c_str());

    // encrypted with pycrypto
    cipher = "Z9VK9h6ttr0uQtdLoBLdjbelZW3BNR+kMY0HFW4F43k=";
    text = decrypt(cipher, password);
    printf("text  : %s\n", text.c_str());

    // encrypted with openssh
//    cipher = "7nkTup43GMmxJX3HtyEUGA==";
//    text = decrypt(cipher, password);
//    printf("text  : %s\n", text.c_str());



}
