/***********************************************************************
* Copyright 2019, San. All rights reserved.
* Author:  San
* Date:    01/04/2019
***********************************************************************/
#include "gtest/gtest.h"
#include "aescipher.h"

TEST(AESCipher, test) {
    std::string text = "hello world";
    std::string password = "password";

    // constructor
    AESCipher a(password);
    std::string enc;
    std::string dec;

    // encrypt and decrypt
    enc = a.encrypt(text);
    printf("%s\n", enc.c_str());
    dec = a.decrypt(enc);
    printf("%s\n", dec.c_str());
    ASSERT_STREQ(text.c_str(), dec.c_str());

    // decrypt from openssl
    enc = "U2FsdGVkX18c4PQDhkrAfE1mY9aMAnx3wCpOy5s1XnY=";
    dec = a.decrypt(enc);
    ASSERT_STREQ(text.c_str(), dec.c_str());
}
