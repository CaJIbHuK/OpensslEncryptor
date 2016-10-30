#include <algorithm>
#include <vector>
#include <string>
#include <iostream>
#include <fstream>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/des.h>

enum class EncType {OTP, AES256, DES};
enum class ContentProviderType {File};

class ContentProvider {
protected:
    ContentProviderType type;
public:
    virtual bool isEOF() const = 0;
    virtual long size() = 0;
    virtual bool write(std::vector<u_char> &buffer) const = 0;
    virtual bool read(std::vector<u_char> &out, std::streamsize  count = 0) const = 0;
};


class FileProvider:ContentProvider{
private:
    std::fstream _file = std::fstream();
public:
    FileProvider(std::string path);
    virtual bool isEOF() const override ;
    long size() override;
    bool write(std::vector<u_char> &buffer) const override;
    bool read(std::vector<u_char> &out, std::streamsize  count = 0) const override;
};

class Encryptor{
private:
    const EVP_CIPHER *type;
    ContentProvider *_in;
    ContentProvider *_out;
    ContentProvider *_key;
    virtual bool validateKey(ContentProvider *keyToSet) = 0;
    virtual bool checkLengthOfKey(long length) = 0;
    virtual bool encdec(Encryptor::EncAction action) = 0;
protected:
    enum class EncAction {DECRYPT = 0, ENCRYPT = 1};
    const ContentProvider* getInCP();
    const ContentProvider* getOutCP();
    const ContentProvider* getKeyCP();
    const EVP_CIPHER* getType();
public:
    Encryptor(const EVP_CIPHER *type, ContentProvider *cpIn, ContentProvider *cpOut, ContentProvider *cpKey);
    void setCtx(ContentProvider* cpIn, ContentProvider* cpOut, ContentProvider* cpKey);
    virtual ~Encryptor();
    virtual bool encrypt() = 0;
    virtual bool decrypt() = 0;
};

class AES256Encryptor:public Encryptor{
private:
    bool validateKey(ContentProvider *keyToSet) override;
    bool checkLengthOfKey(long length) override ;
    bool encdec(Encryptor::EncAction action) override;
public:
    AES256Encryptor(ContentProvider *cpIn,
                 ContentProvider *cpOut,
                 ContentProvider *cpKey):Encryptor(EVP_aes_256_ecb(), cpIn, cpOut, cpKey){};
    bool encrypt();
    bool decrypt();
};

class DESEncryptor:public Encryptor{
private:
    bool validateKey(ContentProvider *keyToSet) override;
    bool checkLengthOfKey(long length) override ;
    bool encdec(Encryptor::EncAction action) override;
public:
    DESEncryptor(ContentProvider *cpIn,
                 ContentProvider *cpOut,
                 ContentProvider *cpKey):Encryptor(EVP_des_ecb(), cpIn, cpOut, cpKey){};
    bool encrypt();
    bool decrypt();
};



//string params (for example, use serializer)
Encryptor* getEncryptor(EncType type,
                        ContentProviderType cpTypeIn,
                        std::string cpParamsIn,
                        ContentProviderType cpTypeOut,
                        std::string cpParamsOut,
                        ContentProviderType cpTypeKey,
                        std::string cpParamsKey,
                        bool generateKey = false);