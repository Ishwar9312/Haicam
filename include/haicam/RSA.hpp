#pragma once


#include "haicam/ByteBuffer.hpp"
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

namespace haicam
{  
    class RSA
    {
    private:
        /* data */
        int ret;
        rsa_st *r;
        BIGNUM *bne;
        int bits;
        BIO    *bp_public;
        BIO    *bp_private;
        unsigned long e;
        

    public:
         RSA(int bits = 128): 
            ret(0), 
            r(NULL),
            bne(NULL),
            bp_private(NULL),
            bp_public(NULL)
            {
                this->bits = bits;
                e = RSA_F4;
            }
        ~RSA();

        bool generateKeyPair(std::string privateKeyPath, std::string publicKeyPath){
            bne = BN_new();
            ret = BN_set_word(bne,e);
            if (ret != 1) {
                BN_free(bne);
                return false;
            }

            r = RSA_new();
            ret = RSA_generate_key_ex(r,bits, bne, NULL);
        
            if (ret != 1) {
                RSA_free(r);
                BN_free(bne);
                return false;
            } 

            FILE* hPrivatefile = NULL;
            hPrivatefile=fopen(privateKeyPath.c_str(),"w+");
            
            if(hPrivatefile == NULL){
                return false;
            }

            bp_private = BIO_new_file(hPrivatefile.c_str(), "w+");
            ret = PEM_write_bio_RSAPrivateKey(bp_private, r, NULL, NULL, 0, NULL, NULL);
            if(ret != 1){
                BIO_free_all(bp_private);
                RSA_free(r);
                BN_free(bne);
                return false;
            }

            FILE* hPublicfile = NULL;
            hPublicfile=fopen(publicKeyPath.c_str(),"w+");
            if(hPublicfile==NULL){
                return false;
              }
            
            bp_public = BIO_new_file(hPublicfile.c_str(), "w+");
            ret = PEM_write_bio_RSA_PUBKEY(bp_public, r);
            if(ret != 1){
                BIO_free_all(bp_public);
                BIO_free_all(bp_private);
                RSA_free(r);
                BN_free(bne);
                return false;
            }
               
            return true;
        }
        bool loadKeyPair(std::string privateKeyPath, std::string publicKeyPath){
           
            FILE* hPrivatefile = NULL;
            hPrivatefile=fopen(privateKeyPath.c_str(),"w+");
            if(hPrivatefile==NULL){
                return false;
              }

            bp_private = BIO_new_file((hPrivatefile, "w+");
            ret = PEM_write_bio_RSAPrivateKey(bp_private, r, NULL, NULL, 0, NULL, NULL);
            if(ret != 1){
                BIO_free_all(bp_private);
                RSA_free(r);
                BN_free(bne);
                return false;
            }

            FILE* hPublicfile = NULL;
            hPublicfile=fopen(publicKeyPath.c_str(),"w+");
            
            if(hPublicfile)==NULL){
                return false;
              }
            
            bp_public = BIO_new_file(hPublicfile, "w+");
            ret = PEM_write_bio_RSA_PUBKEY(bp_public, r);
            if(ret != 1){
                BIO_free_all(bp_public);
                BIO_free_all(bp_private);
                RSA_free(r);
                BN_free(bne);
                return false;
            }
               
            return true;
        }
        
        ByteBufferPtr encrypt(ByteBufferPtr data){
            int len = data.getLength();
            char *encodeData = new char[len+1];
        
            int ret = RSA_public_encrypt(len, (const unsigned char*)data.getData(), (unsigned char*)encodeData, bp_public, RSA_NO_PADDING);
        
            if(ret >= 0){
                std::cerr << "Data encrypted Successully";
            }
            else{
                std::cerr << " error in decryption" ;
            }

            ByteBufferPtr eD;
            return eD.create(encodeData,len+1);
        }
        ByteBufferPtr decrypt(ByteBufferPtr data){
            int len = data.getLength();
            char *decodeData = new char[len+1];
        
            int ret = RSA_private_decrypt(len, (const unsigned char*)data.getData(), (unsigned char*)decodeData, bp_private, RSA_NO_PADDING);
        
            if(ret >= 0){
                std::cerr << "Data decrypted Successully" << decodeData << std::endl;
            }
            else{
                std::cerr << " error in decryption"  ;
            }
            ByteBufferPtr decodeData;
            return decodeData.create(decodeData,len+1);
        }

    };

    // RSA::~RSA(){
    //     // BIO_free_all(bp_public);
    //     // BIO_free_all(bp_private);
    //     // RSA_free(r);
    //     // BN_free(bne);
    // }
}

