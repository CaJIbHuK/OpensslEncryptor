#include "Fabric.h"


//---------------------------FABRIC-------------------------

ContentProvider* EncryptorFabric::getContentProvider(ContentProviderType type, std::string params, ContentDirection direction) {
    switch (type){
        case ContentProviderType::File:
            FileProvider* fp;
            fp = new FileProvider(params, direction);
            return (ContentProvider*)fp;
    }
}

Encryptor* EncryptorFabric::getEncryptor(EncType type, ContentProviderType cpTypeIn, std::string cpParamsIn,
                                         ContentProviderType cpTypeOut, std::string cpParamsOut,
                                         ContentProviderType cpTypeKey, std::string cpParamsKey, bool generateKey) {

    ContentProvider* cpIn = EncryptorFabric::getContentProvider(cpTypeIn, cpParamsIn, ContentDirection::In);
    ContentProvider* cpOut = EncryptorFabric::getContentProvider(cpTypeOut, cpParamsOut, ContentDirection::Out);
    ContentProvider* cpKey = EncryptorFabric::getContentProvider(cpTypeKey, cpParamsKey, generateKey ? ContentDirection::InOut : ContentDirection::In);

    Encryptor* encryptor;

    switch (type) {
        case EncType::AES256:
            encryptor = new AES256Encryptor(cpIn, cpOut, cpKey, generateKey);
            break;
        case EncType::DES:
            encryptor = new DESEncryptor(cpIn, cpOut, cpKey, generateKey);
            break;
        case EncType::DDES:
            encryptor = new DoubleDESEncryptor(cpIn, cpOut, cpKey, generateKey);
            break;
        case EncType::OTP:
            encryptor = new OTPEncryptor(cpIn, cpOut, cpKey, generateKey);
            break;
    }

    return encryptor;
}

Encryptor* EncryptorFabric::getFileEncryptor(EncType type, std::string pathIn, std::string pathOut,
                                             std::string pathKey, bool generateKey) {
    return EncryptorFabric::getEncryptor(type,
                                         ContentProviderType::File, pathIn,
                                         ContentProviderType::File, pathOut,
                                         ContentProviderType::File, pathKey,
                                         generateKey);
}