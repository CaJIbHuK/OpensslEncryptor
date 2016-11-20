#include <algorithm>
#include <vector>
#include <string>
#include <iostream>
#include <fstream>
#include <random>
#include <limits>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/des.h>
#include <openssl/rand.h>

enum class EncType {OTP, AES256, DES, RC4};
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
