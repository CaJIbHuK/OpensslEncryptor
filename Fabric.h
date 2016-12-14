#ifndef FABRIC
#define FABRIC

#include "BaseEncryptor.h"

class EncryptorFabric {
public:
    static std::shared_ptr<Encryptor> getEncryptor(EncType type,
                                                   std::shared_ptr<ContentProvider> cpIn,
                                                   std::shared_ptr<ContentProvider> cpOut,
                                                   std::shared_ptr<ContentProvider> cpKey,
                                                   bool generateKey = false);

    static std::shared_ptr<ContentProvider> getFileContentProvider(ContentDirection direction, std::string params);
    static std::shared_ptr<ContentProvider> getMemoryContentProvider(std::vector<u_char> &initData);
    static std::shared_ptr<ContentProvider> getMemoryContentProvider();
};

#endif