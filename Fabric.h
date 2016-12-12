#ifndef BASE_H
#define BASE_H

#include "BaseEncryptor.h"

#endif

class EncryptorFabric {
public:
    static std::shared_ptr<Encryptor> getEncryptor(EncType type,
                                   ContentProviderType cpTypeIn,
                                   std::string cpParamsIn,
                                   ContentProviderType cpTypeOut,
                                   std::string cpParamsOut,
                                   ContentProviderType cpTypeKey,
                                   std::string cpParamsKey,
                                   bool generateKey = false);
    static std::shared_ptr<ContentProvider> getContentProvider(ContentProviderType type, ContentDirection direction, std::string params);
    static std::shared_ptr<Encryptor> getFileEncryptor(EncType type,
                                       std::string pathIn,
                                       std::string pathOut,
                                       std::string pathKey, bool generateKey = false);
};
