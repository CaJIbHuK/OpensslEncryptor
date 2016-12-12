#include "Fabric.h"
#include "DerivedEncryptor.h"


//---------------------------FABRIC-------------------------

std::shared_ptr<ContentProvider> EncryptorFabric::getContentProvider(ContentProviderType type, ContentDirection direction, std::string params) {
    switch (type){
        case ContentProviderType::File:
            return std::make_shared<FileProvider>(params, direction);
        case ContentProviderType::Memory:
            return std::make_shared<MemoryProvider>();
    }
}

std::shared_ptr<Encryptor> EncryptorFabric::getEncryptor(EncType type, ContentProviderType cpTypeIn, std::string cpParamsIn,
                                         ContentProviderType cpTypeOut, std::string cpParamsOut,
                                         ContentProviderType cpTypeKey, std::string cpParamsKey, bool generateKey) {

    std::shared_ptr<ContentProvider> cpIn = EncryptorFabric::getContentProvider(cpTypeIn, ContentDirection::In, cpParamsIn);
    std::shared_ptr<ContentProvider> cpOut = EncryptorFabric::getContentProvider(cpTypeOut, ContentDirection::Out, cpParamsOut);
    std::shared_ptr<ContentProvider> cpKey = EncryptorFabric::getContentProvider(cpTypeKey, generateKey ? ContentDirection::InOut : ContentDirection::In, cpParamsKey);

    switch (type) {
        case EncType::AES256:
            return std::make_shared<AES256Encryptor>(cpIn, cpOut, cpKey, generateKey);
        case EncType::DES:
            return std::make_shared<DESEncryptor>(cpIn, cpOut, cpKey, generateKey);
        case EncType::OTP:
            return std::make_shared<OTPEncryptor>(cpIn, cpOut, cpKey, generateKey);
        case EncType::RC4:
            return std::make_shared<RC4Encryptor>(cpIn, cpOut, cpKey, generateKey);
        case EncType::DDES:
            return std::make_shared<DDESEncryptor>(cpIn, cpOut, cpKey, generateKey);
    }
}

std::shared_ptr<Encryptor> EncryptorFabric::getFileEncryptor(EncType type, std::string pathIn, std::string pathOut,
                                             std::string pathKey, bool generateKey) {
    return EncryptorFabric::getEncryptor(type,
                                         ContentProviderType::File, pathIn,
                                         ContentProviderType::File, pathOut,
                                         ContentProviderType::File, pathKey,
                                         generateKey);
}