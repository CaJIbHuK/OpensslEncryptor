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
enum class EncAction {DECRYPT = 0, ENCRYPT = 1};
enum class ContentProviderType {File};


class ContentProvider {
protected:
    ContentProviderType type;
public:
    virtual bool isEOF() const = 0;
    virtual long size() = 0;
    virtual bool write(std::vector<u_char> &buffer) = 0;
    virtual bool read(std::vector<u_char> &out, std::streamsize  count = 0) = 0;
};


class FileProvider:ContentProvider{
private:
    std::fstream _file;
public:
    FileProvider(std::string path);
    virtual bool isEOF() const override ;
    long size() override;
    bool write(std::vector<u_char> &buffer) override;
    bool read(std::vector<u_char> &out, std::streamsize  count = 0) override;
};

class Encryptor{
private:
    const EVP_CIPHER *type;
    ContentProvider *_in;
    ContentProvider *_out;
    ContentProvider *_key;
    virtual bool validateKey(ContentProvider *keyToSet);
    virtual bool checkLengthOfKey(long length) = 0;
    virtual bool encdec(EncAction action) = 0;
protected:
    ContentProvider* getInCP();
    ContentProvider* getOutCP();
    ContentProvider* getKeyCP();
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
    bool encdec(EncAction action) override;
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
    bool encdec(EncAction action) override;
public:
    DESEncryptor(ContentProvider *cpIn,
                 ContentProvider *cpOut,
                 ContentProvider *cpKey):Encryptor(EVP_des_ecb(), cpIn, cpOut, cpKey){};
    bool encrypt();
    bool decrypt();
};

class OTPEncryptor:public Encryptor{
private:
    bool validateKey(ContentProvider *keyToSet) override;
    bool checkLengthOfKey(long length) override ;
    bool encdec(EncAction action) override;
public:
    OTPEncryptor(ContentProvider *cpIn,
                 ContentProvider *cpOut,
                 ContentProvider *cpKey):Encryptor(NULL, cpIn, cpOut, cpKey){};
    bool encrypt();
    bool decrypt();
};


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
    static ContentProvider* getContentProvider(ContentProviderType type, std::string params);
};
//string params (for example, use serializer)
