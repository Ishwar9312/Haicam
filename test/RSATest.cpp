#include "gtest/gtest.h"
#include "haicam/RSA.hpp"

using namespace haicam;

TEST(haicam_RSATest, rsa_test){
    RSA rsa(128);
    rsa.generateKeyPair("/home/ishwar/keys/public_keys.txt","/home/ishwar/keys/private_keys.txt");
    std::string st = "hello world";
    rsa.encrypt((char *)st.c_str()));
    ByteBufferPtr temp = rsa.decrypt((char *)st.c_str());
   // ASSERT_EQ(temp.getData(), st.c_str());
}
