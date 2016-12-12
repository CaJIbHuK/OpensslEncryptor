#include "BaseEncryptor.h"

Encryptor::Encryptor(std::shared_ptr<ContentProvider> cpIn, std::shared_ptr<ContentProvider> cpOut, std::shared_ptr<ContentProvider> cpKey) {
    this->setCtx(cpIn, cpOut, cpKey);
}

Encryptor::~Encryptor() { }

void Encryptor::processKey(bool generateKey) {
    auto keyCP = this->getKeyCP();
    if (generateKey) {
        std::vector<u_char> key;
        if (!this->generateKey(key)) throw 500;
        keyCP->write(key);
        keyCP->init();
    } else {
        if (!this->validateKey(keyCP)) throw 400;
    }
}

bool Encryptor::validateKey(std::shared_ptr<ContentProvider> keyToSet) {
    return this->checkLengthOfKey(keyToSet->size(false));
}

std::shared_ptr<ContentProvider> Encryptor::getInCP() {return this->_in;}
std::shared_ptr<ContentProvider> Encryptor::getOutCP() {return this->_out;}
std::shared_ptr<ContentProvider> Encryptor::getKeyCP() {return this->_key;}

void Encryptor::setCtx(std::shared_ptr<ContentProvider> cpIn, std::shared_ptr<ContentProvider> cpOut, std::shared_ptr<ContentProvider> cpKey) {
    this->_in = cpIn;
    this->_out = cpOut;
    this->_key = cpKey;
    this->_in->init();
    this->_out->init();
    this->_key->init();
}
