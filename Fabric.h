#ifndef BASE_H
#define BASE_H

#include "BaseEncryptor.h"

#endif

class EncryptorFabric {
public:
    static std::shared_ptr<Encryptor> getEncryptor(EncType type,
                                                   std::shared_ptr<ContentProvider> cpIn,
                                                   std::shared_ptr<ContentProvider> cpOut,
                                                   std::shared_ptr<ContentProvider> cpKey,
                                                   bool generateKey = false);

    static std::shared_ptr<ContentProvider> getContentProvider(ContentProviderType type, ContentDirection direction, std::string params);

    static std::shared_ptr<Encryptor> getFileEncryptor(EncType type,
                                                       std::string pathIn,
                                                       std::string pathOut,
                                                       std::string pathKey, bool generateKey = false);

    static std::shared_ptr<Encryptor> getMemoryEncryptor(EncType type,
                                                         std::vector<u_char> &dataIn,
                                                         std::vector<u_char> &key,
                                                         bool generateKey);
};
