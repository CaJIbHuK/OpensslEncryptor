#ifndef RC4_ENCRYPTOR
#define RC4_ENCRYPTOR

#include "BaseEncryptor.h"

class RC4Encryptor:public Encryptor{
private:
    class RC4KeyGenerator{
    private:
        std::vector<u_char> s;
        u_char x = 0;
        u_char y = 0;
    public:
        RC4KeyGenerator(std::vector<u_char> &key);
        const u_char* next();
    };

    RC4KeyGenerator *keyGen;
    bool checkLengthOfKey(long length) override ;
    bool encdec(EncAction action) override;
    bool generateKey(std::vector<u_char> &key) override;
public:
    RC4Encryptor(std::shared_ptr<ContentProvider> cpIn,
                 std::shared_ptr<ContentProvider> cpOut,
                 std::shared_ptr<ContentProvider> cpKey,
                 bool generateKey);
    bool encrypt();
    bool decrypt();
};

#endif