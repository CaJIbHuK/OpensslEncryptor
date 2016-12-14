#include "DESEncryptor.h"
#include "common_openssl.h"
#include "common.h"


//---------------------------DES---------------------------
DESEncryptor::DESEncryptor(std::shared_ptr<ContentProvider> cpIn, std::shared_ptr<ContentProvider> cpOut, std::shared_ptr<ContentProvider> cpKey,
                           bool generateKey) : Encryptor(cpIn, cpOut, cpKey) {
    this->processKey(generateKey);
}

bool DESEncryptor::checkLengthOfKey(long length) {
    return length == 8;
}

bool DESEncryptor::generateKey(std::vector<u_char> &key) {
    key.assign(8, 0);
    return RAND_bytes(key.data(), 8) == 1;
}

void DESEncryptor::addPadding(std::vector<u_char> &block, int blockLength) {
    auto lengthOfPadding = blockLength - block.size();
    for (int i = 0; i < lengthOfPadding+7; ++i) {
        block.push_back(0);
    }
    block.push_back((u_char)lengthOfPadding);
}

void DESEncryptor::removePadding(std::vector<u_char> &block) {
    auto lengthOfPadding = (*(block.end()-1));
    if (lengthOfPadding > 8) return;

    int i = 1;
    auto paddingIt = block.end()-2;
    for (; i < lengthOfPadding; paddingIt--, i++) {
        if ((*paddingIt) != 0) break;
    }

    if (i == lengthOfPadding) {
        block.erase(paddingIt+1, block.end());
    }
}

bool DESEncryptor::encdec(EncAction action) {

    auto currAction = action == EncAction::ENCRYPT ? DES_ENCRYPT : DES_DECRYPT;

    std::vector<u_char> key;
    if (!this->getKeyCP()->read(key, 8)) return false;

    auto inCP = this->getInCP();
    auto outCP = this->getOutCP();

    int readBlockSize = 8;
    int paddingLength = -1;
    unsigned char outbuff[readBlockSize];
    std::vector<u_char> currBlock;

    DES_cblock      desKey;
    DES_key_schedule schedule;

    std::copy(key.begin(), key.end(), desKey);

    DES_set_odd_parity(&desKey);
    DES_set_key_checked(&desKey, &schedule);

    for(;;)
    {
        currBlock.clear();

        if (!inCP->read(currBlock,readBlockSize)) false;

        if (action == EncAction::ENCRYPT && inCP->isEOData()) {
            paddingLength = readBlockSize - currBlock.size();
            if (paddingLength) this->addPadding(currBlock, readBlockSize);
        }

        DES_ecb_encrypt((DES_cblock *) currBlock.data(), (DES_cblock *) outbuff, &schedule, currAction);

        std::vector<u_char> writeBuffer(outbuff, outbuff + readBlockSize);

        if (action == EncAction::DECRYPT && inCP->isEOData()) {
            this->removePadding(writeBuffer);
        }

        outCP->write(writeBuffer);

        if (inCP->isEOData()) break;
    }

    if (action == EncAction::ENCRYPT && paddingLength == 0) {
        currBlock.clear();
        currBlock.assign(7,0);
        currBlock.push_back(8);
        DES_ecb_encrypt((DES_cblock *) currBlock.data(), (DES_cblock *) outbuff, &schedule, currAction);
        std::vector<u_char> writeBuffer(outbuff, outbuff + readBlockSize);
        outCP->write(writeBuffer);
    }

    return true;
}

bool DESEncryptor::encrypt() {
    return this->encdec(EncAction::ENCRYPT);
}

bool DESEncryptor::decrypt() {
    return this->encdec(EncAction::DECRYPT);
}
//---------------------------DDES---------------------------
DDESEncryptor::DDESEncryptor(std::shared_ptr<ContentProvider> cpIn, std::shared_ptr<ContentProvider> cpOut, std::shared_ptr<ContentProvider> cpKey,
                             bool generateKey) : Encryptor(cpIn, cpOut, cpKey) {
    this->processKey(generateKey);
}

bool DDESEncryptor::checkLengthOfKey(long length) {
    return length == 16;
}

bool DDESEncryptor::generateKey(std::vector<u_char> &key) {
    key.assign(16, 0);
    return RAND_bytes(key.data(), 16) == 1;
}

void DDESEncryptor::addPadding(std::vector<u_char> &block, int blockLength) {
    auto lengthOfPadding = blockLength - block.size();
    for (int i = 0; i < lengthOfPadding+7; ++i) {
        block.push_back(0);
    }
    block.push_back((u_char)lengthOfPadding);
}

void DDESEncryptor::removePadding(std::vector<u_char> &block) {
    auto lengthOfPadding = (*(block.end()-1));
    if (lengthOfPadding > 8) return;

    int i = 1;
    auto paddingIt = block.end()-2;
    for (; i < lengthOfPadding; paddingIt--, i++) {
        if ((*paddingIt) != 0) break;
    }

    if (i == lengthOfPadding) {
        block.erase(paddingIt+1, block.end());
    }
}

bool DDESEncryptor::encdec(EncAction action) {

    std::vector<u_char> key1;
    std::vector<u_char> key2;
    if (!this->getKeyCP()->read(key1, 8)) return false;
    if (!this->getKeyCP()->read(key2, 8)) return false;

    std::shared_ptr<ContentProvider> desKey1 = std::make_shared<MemoryProvider>(key1);
    std::shared_ptr<ContentProvider> desKey2 = std::make_shared<MemoryProvider>(key2);

    auto inCP = this->getInCP();
    auto outCP = this->getOutCP();
    std::shared_ptr<ContentProvider> intermediateResult = std::make_shared<MemoryProvider>();

    if (action == EncAction::ENCRYPT){
        DESEncryptor des1(inCP, intermediateResult, desKey1, false);
        des1.encrypt();
        DESEncryptor des2(intermediateResult, outCP, desKey2, false);
        des2.encrypt();
    } else {
        DESEncryptor des1(inCP, intermediateResult, desKey2, false);
        des1.decrypt();
        DESEncryptor des2(intermediateResult, outCP, desKey1, false);
        des2.decrypt();
    }

    return true;
}

bool DDESEncryptor::encrypt() {
    return this->encdec(EncAction::ENCRYPT);
}

bool DDESEncryptor::decrypt() {
    return this->encdec(EncAction::DECRYPT);
}
