#include "encFabric.h"

//------------------------FILE PROVIDER-------------------------
FileProvider::FileProvider(std::string path) {
    this->_file.open(path,
                     std::basic_ios::in
                     |std::basic_ios::out
                     |std::basic_ios::binary
                     |std::basic_ios::app);
    this->type = ContentProviderType::File;
}

long FileProvider::size() {
    return this->_file.tellg();
}

bool FileProvider::isEOF() const {
    return this->_file.eof();
}

bool FileProvider::read(std::vector<u_char> &out, std::streamsize count = 0) const {
    out.clear();
    std::fstream &file = this->_file;
    if (!file.is_open()) return false;

    if (count == 0) count = file.tellg();
    char *buffer = new char[count];
    file.read(buffer, count);
    if (file.bad()) return false;

    std::streamsize amountOfReadBytes = file.gcount();
    for (std::streamsize i = 0; i < amountOfReadBytes; ++i) {
        out.push_back((u_char)buffer[i]);
    }

    if (this->isEOF()) this->_file.close();

    return true;
}

bool FileProvider::write(std::vector<u_char> &buffer) const {
    std::fstream &file = this->_file;
    if (!file.is_open()) return false;
    file.write(buffer.data(), buffer.size());
    return !file.bad();
}

//------------------------ENCRYPTOR-------------------------
Encryptor::Encryptor(const EVP_CIPHER *type, ContentProvider *cpIn, ContentProvider *cpOut, ContentProvider *cpKey) {
    if (!this->validateKey(cpKey)) throw 400;
    this->type = type;
    this->setCtx(cpIn, cpOut, cpKey);
}

Encryptor::~Encryptor() { delete this->_in; delete this->_out; delete this->_key; delete this->type;}

const ContentProvider* Encryptor::getInCP() {return this->_in;}
const ContentProvider* Encryptor::getOutCP() {return this->_out;}
const ContentProvider* Encryptor::getKeyCP() {return this->_key;}
const EVP_CIPHER* Encryptor::getType() {return this->type;}

void Encryptor::setCtx(ContentProvider *cpIn, ContentProvider *cpOut, ContentProvider *cpKey) {
    if (cpIn != NULL) this->_in = cpIn;
    if (cpOut != NULL) this->_out = cpOut;
    if (cpKey != NULL) this->_key = cpKey;
}

//---------------------------AES256---------------------------
bool AES256Encryptor::checkLengthOfKey(long length) {
    return length == 32;
}

bool AES256Encryptor::validateKey(ContentProvider *keyToSet) {
    return this->checkLengthOfKey(keyToSet->size());
}

bool AES256Encryptor::encdec(Encryptor::EncAction action) {

    int outlen;
    int readBlockSize = 1024;
    int outbufSize = readBlockSize + EVP_MAX_BLOCK_LENGTH;
    unsigned char outbuff[outbufSize];
    std::vector<u_char> currBlock;

    std::vector<u_char> key;
    if (!this->getKeyCP()->read(key)) return false;

    auto inCP = this->getInCP();
    auto outCP = this->getOutCP();

    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit_ex(&ctx, this->getType(), NULL, key.data(), NULL, static_cast<int>(action));

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
bool DESEncryptor::checkLengthOfKey(long length) {
    return length == 8;
}

bool DESEncryptor::validateKey(ContentProvider *keyToSet) {
    return this->checkLengthOfKey(keyToSet->size());
}

bool DESEncryptor::encdec(Encryptor::EncAction action) {

    auto currAction = action == EncAction::ENCRYPT ? DES_ENCRYPT : DES_DECRYPT;

    std::vector<u_char> key;
    if (!this->getKeyCP()->read(key)) return false;

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


