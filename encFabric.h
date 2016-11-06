#include <algorithm>
#include <vector>
#include <string>
#include <iostream>
#include <fstream>
#include <iostream>
#include <random>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/des.h>
#include <openssl/rand.h>

enum class EncType {OTP, AES256, DES};
enum class EncAction {DECRYPT = 0, ENCRYPT = 1};
enum class ContentProviderType {File};
enum class ContentDirection {In, Out, InOut};


class ContentProvider {
protected:
    ContentProviderType type;
    long cachedSize;
public:
    virtual void init() = 0;
    virtual bool isEOData() const = 0;
    virtual long size(bool useCachedValue = true) = 0;
    virtual bool write(std::vector<u_char> &buffer) = 0;
    virtual bool read(std::vector<u_char> &out, std::streamsize  count = 0) = 0;
};


class FileProvider:ContentProvider{
private:
    std::fstream _file;
public:
    FileProvider(std::string path, ContentDirection direction);
    virtual void init() override;
    virtual bool isEOData() const override ;
    long size(bool useCachedValue = true) override;
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
    virtual bool generateKey(std::vector<u_char> &key) = 0;
protected:
    void processKey(bool generateKey = false);
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
    bool checkLengthOfKey(long length) override ;
    bool encdec(EncAction action) override;
    bool generateKey(std::vector<u_char> &key) override;
public:
    AES256Encryptor(ContentProvider *cpIn,
                    ContentProvider *cpOut,
                    ContentProvider *cpKey,
                    bool generateKey = false);
    bool encrypt();
    bool decrypt();
};

class DESEncryptor:public Encryptor{
private:
    bool checkLengthOfKey(long length) override ;
    bool encdec(EncAction action) override;
    bool generateKey(std::vector<u_char> &key) override;
    void addPadding(std::vector<u_char> &block, int blockLength);
    void removePadding(std::vector<u_char> &block);
public:
    DESEncryptor(ContentProvider *cpIn,
                 ContentProvider *cpOut,
                 ContentProvider *cpKey,
                 bool generateKey = false);
    bool encrypt();
    bool decrypt();
};

class OTPEncryptor:public Encryptor{
private:
    bool checkLengthOfKey(long length) override ;
    bool encdec(EncAction action) override;
    bool generateKey(std::vector<u_char> &key) override;
public:
    OTPEncryptor(ContentProvider *cpIn,
                 ContentProvider *cpOut,
                 ContentProvider *cpKey,
                 bool generateKey = false);
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
    static ContentProvider* getContentProvider(ContentProviderType type, std::string params, ContentDirection direction);
    static Encryptor* getFileEncryptor(EncType type,
                                       std::string pathIn,
                                       std::string pathOut,
                                       std::string pathKey, bool generateKey = false);
};
