#ifndef AES_ENCRYPTOR
#define AES_ENCRYPTOR

#include "BaseEncryptor.h"

class AES256Encryptor:public Encryptor{
private:
    bool checkLengthOfKey(long length) override ;
    bool encdec(EncAction action) override;
    bool generateKey(std::vector<u_char> &key) override;
public:
    AES256Encryptor(std::shared_ptr<ContentProvider> cpIn,
                    std::shared_ptr<ContentProvider> cpOut,
                    std::shared_ptr<ContentProvider> cpKey,
                    bool generateKey);
    bool encrypt();
    bool decrypt();

};

#endif