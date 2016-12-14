#include "AESEncryptor.h"
#include "common_openssl.h"
#include "common.h"

AES256Encryptor::AES256Encryptor(std::shared_ptr<ContentProvider> cpIn, std::shared_ptr<ContentProvider> cpOut, std::shared_ptr<ContentProvider> cpKey,
                                 bool generateKey) : Encryptor(cpIn, cpOut, cpKey) {
    this->processKey(generateKey);
}

bool AES256Encryptor::checkLengthOfKey(long length) {
    return length == 32;
}

bool AES256Encryptor::generateKey(std::vector<u_char> &key) {
    key.assign(32, 0);
    return RAND_bytes(key.data(), 32) == 1;
}

bool AES256Encryptor::encdec(EncAction action) {

    int outlen;
    int readBlockSize = 1024;
    int outbufSize = readBlockSize + EVP_MAX_BLOCK_LENGTH;
    unsigned char outbuff[outbufSize];
    std::vector<u_char> currBlock;

    std::vector<u_char> key;
    if (!this->getKeyCP()->read(key, 32)) return false;

    auto inCP = this->getInCP();
    auto outCP = this->getOutCP();

    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit_ex(ctx, EVP_aes_256_ecb(), NULL, key.data(), NULL, static_cast<int>(action));

    for(;;)
    {
        currBlock.clear();

        if (!inCP->read(currBlock,readBlockSize)) false;

        if(!EVP_CipherUpdate(ctx, outbuff, &outlen, currBlock.data(), currBlock.size()))
        {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }

        std::vector<u_char> writeBuffer(outbuff, outbuff+outlen);
        outCP->write(writeBuffer);

        if (inCP->isEOData()) break;
    }

    if(!EVP_CipherFinal_ex(ctx, outbuff, &outlen))
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    std::vector<u_char> writeBuffer(outbuff, outbuff+outlen);
    outCP->write(writeBuffer);

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bool AES256Encryptor::encrypt() {
    return this->encdec(EncAction::ENCRYPT);
}

bool AES256Encryptor::decrypt() {
    return this->encdec(EncAction::DECRYPT);
}


