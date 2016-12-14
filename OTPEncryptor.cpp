#include "OTPEncryptor.h"
#include "common_openssl.h"
#include "common.h"


OTPEncryptor::OTPEncryptor(std::shared_ptr<ContentProvider> cpIn, std::shared_ptr<ContentProvider> cpOut, std::shared_ptr<ContentProvider> cpKey,
                           bool generateKey) : Encryptor(cpIn, cpOut, cpKey) {
    this->processKey(generateKey);
}

bool OTPEncryptor::checkLengthOfKey(long length) {
    return length >= this->getInCP()->size();
}

bool OTPEncryptor::generateKey(std::vector<u_char> &key) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<u_char> dist(0, 255);
    for (long i = 0; i < this->getInCP()->size(); ++i) {
        key.push_back(dist(gen));
    }
    return true;
}

bool OTPEncryptor::encdec(EncAction action) {

    auto inCP = this->getInCP();
    auto outCP = this->getOutCP();
    auto keyCP = this->getKeyCP();

    int readBlockSize = 1024;
    std::vector<u_char> currBlock;
    std::vector<u_char> currKey;
    std::vector<u_char> currResult;

    for(;;)
    {
        currBlock.clear();
        currKey.clear();
        currResult.clear();

        if (!inCP->read(currBlock, readBlockSize)) false;
        if (!keyCP->read(currKey, readBlockSize)) false;

        //we assume that sizes of block and key are equal
        //because of initial validation of key size
        for (int i = 0; i < currBlock.size(); ++i)
            currResult.push_back(currBlock[i]^currKey[i]);

        outCP->write(currResult);

        if (inCP->isEOData()) break;
    }

    return true;
}

bool OTPEncryptor::encrypt() {
    return this->encdec(EncAction::ENCRYPT);
}

bool OTPEncryptor::decrypt() {
    return this->encdec(EncAction::DECRYPT);
}
