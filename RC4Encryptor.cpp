#include "RC4Encryptor.h"
#include "common.h"
#include "common_openssl.h"


RC4Encryptor::RC4KeyGenerator::RC4KeyGenerator(std::vector<u_char> &key) {
    for (u_char i = 0; i < std::numeric_limits<u_char>::max(); ++i) {
        s.push_back(i);
    }
    u_char j = 0;
    for (u_char i = 0; i < std::numeric_limits<u_char>::max(); ++i) {
        j = (j + this->s[i] + key[i % key.size()]) + s[i];
        std::swap(s[i], s[j]);
    }
}

 const u_char* RC4Encryptor::RC4KeyGenerator::next() {
    this->x++;
    this->y+=s[x];
    std::swap(s[x],s[y]);
    return &s[(s[x] + s[y])%std::numeric_limits<u_char>::max()];
}


 RC4Encryptor::RC4Encryptor(std::shared_ptr<ContentProvider> cpIn, std::shared_ptr<ContentProvider> cpOut, std::shared_ptr<ContentProvider> cpKey,
                           bool generateKey) : Encryptor(cpIn, cpOut, cpKey) {
    this->processKey(generateKey);

    std::vector<u_char> key;
    this->getKeyCP()->read(key);
    this->keyGen = new RC4KeyGenerator(key);
}

 bool RC4Encryptor::checkLengthOfKey(long length) {
    return true;
}


 bool RC4Encryptor::generateKey(std::vector<u_char> &key) {
    key.assign(256, 0);
    return RAND_bytes(key.data(), 256) == 1;
}

 bool RC4Encryptor::encdec(EncAction action) {

    auto inCP = this->getInCP();
    auto outCP = this->getOutCP();

    int readBlockSize = sizeof(u_char);
    const u_char *currKey;
    std::vector<u_char> currBlock;
    std::vector<u_char> currResult;

    for(;;)
    {
        currKey = this->keyGen->next();
        currBlock.clear();
        currResult.clear();

        if (!inCP->read(currBlock, readBlockSize)) false;

        for (int i = 0; i < currBlock.size(); ++i)
            currResult.push_back(currBlock[i]^currKey[i]);

        outCP->write(currResult);

        if (inCP->isEOData()) break;
    }

    return true;
}

 bool RC4Encryptor::encrypt() {
    return this->encdec(EncAction::ENCRYPT);
}

 bool RC4Encryptor::decrypt() {
    return this->encdec(EncAction::DECRYPT);
}
