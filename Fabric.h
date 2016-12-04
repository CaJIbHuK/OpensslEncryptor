#ifndef BASE_H
#define BASE_H

#include "BaseEncryptor.h"

#endif

class EncryptorFabric {
public:
    static Encryptor* getEncryptor(EncType type,
                                   ContentProviderType cpTypeIn,
                                   std::string cpParamsIn,
                                   ContentProviderType cpTypeOut,
                                   std::string cpParamsOut,
                                   ContentProviderType cpTypeKey,
                                   std::string cpParamsKey,
                                   bool generateKey = false);
    static ContentProvider* getContentProvider(ContentProviderType type, std::string params, ContentDirection direction);
    static Encryptor* getFileEncryptor(EncType type,
                                       std::string pathIn,
                                       std::string pathOut,
                                       std::string pathKey, bool generateKey = false);
};
