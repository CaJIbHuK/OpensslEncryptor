#include "Fabric.h"
#include "ContentProviders.h"
#include "AESEncryptor.h"
#include "DESEncryptor.h"
#include "OTPEncryptor.h"
#include "RC4Encryptor.h"

std::shared_ptr<ContentProvider> EncryptorFabric::getFileContentProvider(ContentDirection direction = ContentDirection::InOut, std::string params = "") {
    return std::make_shared<FileProvider>(params, direction);
}
std::shared_ptr<ContentProvider> EncryptorFabric::getMemoryContentProvider(std::vector<u_char> &initData) {
    return std::make_shared<MemoryProvider>(initData);
}
std::shared_ptr<ContentProvider> EncryptorFabric::getMemoryContentProvider() {
    return std::make_shared<MemoryProvider>();
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
