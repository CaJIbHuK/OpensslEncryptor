#include "Fabric.h"
#include "DerivedEncryptor.h"


//---------------------------FABRIC-------------------------
//TODO params - ContentProviderParams*
std::shared_ptr<ContentProvider> EncryptorFabric::getContentProvider(ContentProviderType type, ContentDirection direction = ContentDirection::InOut, std::string params = "") {
    switch (type){
        case ContentProviderType::File:
            return std::make_shared<FileProvider>(params, direction);
        case ContentProviderType::Memory:
            return std::make_shared<MemoryProvider>();
    }
}

std::shared_ptr<Encryptor> EncryptorFabric::getEncryptor(EncType type,
                                                         std::shared_ptr<ContentProvider> cpIn,
                                                         std::shared_ptr<ContentProvider> cpOut,
                                                         std::shared_ptr<ContentProvider> cpKey,
                                                         bool generateKey) {
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

std::shared_ptr<Encryptor> EncryptorFabric::getFileEncryptor(EncType type,
                                                             std::string pathIn,
                                                             std::string pathOut,
                                                             std::string pathKey,
                                                             bool generateKey) {

    std::shared_ptr<ContentProvider> cpIn = EncryptorFabric::getContentProvider(ContentProviderType::File, ContentDirection::In, pathIn);
    std::shared_ptr<ContentProvider> cpOut = EncryptorFabric::getContentProvider(ContentProviderType::File , ContentDirection::Out, pathOut);
    std::shared_ptr<ContentProvider> cpKey = EncryptorFabric::getContentProvider(ContentProviderType::File, generateKey ? ContentDirection::InOut : ContentDirection::In, pathKey);

    return EncryptorFabric::getEncryptor(type,cpIn, cpOut, cpKey, generateKey);
}

std::shared_ptr<Encryptor> EncryptorFabric::getMemoryEncryptor(EncType type,
                                                               std::vector<u_char> &dataIn,
                                                               std::vector<u_char> &key,
                                                               bool generateKey) {

    std::shared_ptr<ContentProvider> cpIn = EncryptorFabric::getContentProvider(ContentProviderType::Memory);
    std::shared_ptr<ContentProvider> cpOut = EncryptorFabric::getContentProvider(ContentProviderType::Memory);
    std::shared_ptr<ContentProvider> cpKey = EncryptorFabric::getContentProvider(ContentProviderType::Memory);

    cpIn->write(dataIn);
    if (!generateKey) cpKey->write(key);

    return EncryptorFabric::getEncryptor(type,cpIn, cpOut, cpKey, generateKey);
}