#include "encFabric.h"

//------------------------FILE PROVIDER-------------------------
FileProvider::FileProvider(std::string path) {
    this->_file.open(path, std::ios::in
                           |std::ios::out
                           |std::ios::binary
                           |std::ios::app);
    this->type = ContentProviderType::File;
}

long FileProvider::size(bool useCachedValue) {
    if (this->cachedSize && useCachedValue) return this->cachedSize;

    auto currPos = this->_file.tellg();
    long length = 0;
    this->_file.seekg(0, this->_file.end);

    length = this->_file.tellg();
    this->cachedSize = length;

    this->_file.seekg(currPos);

    return length;
}

bool FileProvider::isEOF() const {
    return this->_file.eof();
}

bool FileProvider::read(std::vector<u_char> &out, std::streamsize count) {
    out.clear();
    if (!this->_file.is_open()) return false;

    if (count == 0) count = this->size();

    char *buffer = new char[count];
    this->_file.read(buffer, count);
    if (this->_file.bad()) return false;

    std::streamsize amountOfReadBytes = this->_file.gcount();
    for (std::streamsize i = 0; i < amountOfReadBytes; ++i) {
        out.push_back((u_char)buffer[i]);
    }

    if (this->isEOF()) this->_file.close();

    return true;
}

bool FileProvider::write(std::vector<u_char> &buffer) {
    if (!this->_file.is_open()) return false;
    this->_file.write((char*)buffer.data(), buffer.size());
    return !this->_file.bad();
}

//------------------------ENCRYPTOR-------------------------
Encryptor::Encryptor(const EVP_CIPHER *type, ContentProvider *cpIn, ContentProvider *cpOut, ContentProvider *cpKey) {
    this->type = type;
    this->setCtx(cpIn, cpOut, cpKey);
}

Encryptor::~Encryptor() { delete this->_in; delete this->_out; delete this->_key; delete this->type;}

void Encryptor::processKey(bool generateKey) {
    auto keyCP = this->getKeyCP();
    if (generateKey) {
        std::vector<u_char> key;
        if (!this->generateKey(key)) throw 500;
        keyCP->write(key);
    } else {
        if (!this->validateKey(keyCP)) throw 400;
    }
}

ContentProvider* Encryptor::getInCP() {return this->_in;}
ContentProvider* Encryptor::getOutCP() {return this->_out;}
ContentProvider* Encryptor::getKeyCP() {return this->_key;}
const EVP_CIPHER* Encryptor::getType() {return this->type;}

void Encryptor::setCtx(ContentProvider *cpIn, ContentProvider *cpOut, ContentProvider *cpKey) {
    if (cpIn != NULL) this->_in = cpIn;
    if (cpOut != NULL) this->_out = cpOut;
    if (cpKey != NULL) this->_key = cpKey;
}

//---------------------------AES256---------------------------

AES256Encryptor::AES256Encryptor(ContentProvider *cpIn, ContentProvider *cpOut, ContentProvider *cpKey,
                                 bool generateKey) : Encryptor(EVP_aes_256_ecb(), cpIn, cpOut, cpKey) {
    this->processKey(generateKey);
}

bool AES256Encryptor::checkLengthOfKey(long length) {
    return length == 32;
}

bool AES256Encryptor::validateKey(ContentProvider *keyToSet) {
    return this->checkLengthOfKey(keyToSet->size());
}

bool AES256Encryptor::generateKey(std::vector<u_char> &key) {
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
    EVP_CipherInit_ex(ctx, this->getType(), NULL, key.data(), NULL, static_cast<int>(action));

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

        if (inCP->isEOF()) break;
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

//---------------------------DES---------------------------
DESEncryptor::DESEncryptor(ContentProvider *cpIn, ContentProvider *cpOut, ContentProvider *cpKey,
                                 bool generateKey) : Encryptor(EVP_des_ecb(), cpIn, cpOut, cpKey) {
    this->processKey(generateKey);
}

bool DESEncryptor::checkLengthOfKey(long length) {
    return length == 8;
}

bool DESEncryptor::validateKey(ContentProvider *keyToSet) {
    return this->checkLengthOfKey(keyToSet->size());
}

bool DESEncryptor::generateKey(std::vector<u_char> &key) {
    return RAND_bytes(key.data(), 8) == 1;
}

bool DESEncryptor::encdec(EncAction action) {

    auto currAction = action == EncAction::ENCRYPT ? DES_ENCRYPT : DES_DECRYPT;

    std::vector<u_char> key;
    if (!this->getKeyCP()->read(key, 8)) return false;

    auto inCP = this->getInCP();
    auto outCP = this->getOutCP();

    int readBlockSize = 8;
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

        if (currBlock.size() < readBlockSize) {
            for (int i = 0; i < readBlockSize - currBlock.size(); ++i) {
                currBlock.push_back(0);
            }
        }
        DES_ecb_encrypt((DES_cblock*)currBlock.data(), (DES_cblock*)outbuff,  &schedule, currAction);

        std::vector<u_char> writeBuffer(outbuff, outbuff+readBlockSize);
        outCP->write(writeBuffer);

        if (inCP->isEOF()) break;
    }

    return true;
}

bool DESEncryptor::encrypt() {
    return this->encdec(EncAction::ENCRYPT);
}

bool DESEncryptor::decrypt() {
    return this->encdec(EncAction::DECRYPT);
}


//---------------------------OTP---------------------------
OTPEncryptor::OTPEncryptor(ContentProvider *cpIn, ContentProvider *cpOut, ContentProvider *cpKey,
                                 bool generateKey) : Encryptor(NULL, cpIn, cpOut, cpKey) {
    this->processKey(generateKey);
}

bool OTPEncryptor::checkLengthOfKey(long length) {
    return length == this->getInCP()->size();
}

bool OTPEncryptor::validateKey(ContentProvider *keyToSet) {
    return this->checkLengthOfKey(keyToSet->size());
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

        if (inCP->isEOF()) break;
    }

    return true;
}

bool OTPEncryptor::encrypt() {
    return this->encdec(EncAction::ENCRYPT);
}

bool OTPEncryptor::decrypt() {
    return this->encdec(EncAction::DECRYPT);
}


//---------------------------FABRIC-------------------------

ContentProvider* EncryptorFabric::getContentProvider(ContentProviderType type, std::string params) {
    switch (type){
        case ContentProviderType::File:
            FileProvider* fp;
            fp = new FileProvider(params);
            return (ContentProvider*)fp;
    }
}

Encryptor* EncryptorFabric::getEncryptor(EncType type, ContentProviderType cpTypeIn, std::string cpParamsIn,
                                         ContentProviderType cpTypeOut, std::string cpParamsOut,
                                         ContentProviderType cpTypeKey, std::string cpParamsKey, bool generateKey) {

    ContentProvider* cpIn = EncryptorFabric::getContentProvider(cpTypeIn, cpParamsIn);
    ContentProvider* cpOut = EncryptorFabric::getContentProvider(cpTypeOut, cpParamsOut);
    ContentProvider* cpKey = EncryptorFabric::getContentProvider(cpTypeKey, cpParamsKey);

    Encryptor* encryptor;

    switch (type) {
        case EncType::AES256:
            encryptor = new AES256Encryptor(cpIn, cpOut, cpKey, generateKey);
            break;
        case EncType::DES:
            encryptor = new DESEncryptor(cpIn, cpOut, cpKey, generateKey);
            break;
        case EncType::OTP:
            encryptor = new OTPEncryptor(cpIn, cpOut, cpKey, generateKey);
            break;
    }

    return encryptor;
}

