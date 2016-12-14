#ifndef BASE_ENCRYPTOR
#define BASE_ENCRYPTOR

#include <vector>
#include <string>
#include <memory>

enum class EncType {OTP, AES256, DES, RC4, DDES};
enum class EncAction {DECRYPT = 0, ENCRYPT = 1};
enum class ContentProviderType {File, Memory};
enum class ContentDirection {In, Out, InOut};

class ContentProvider {
protected:
    ContentProviderType type;
    long cachedSize = 0;
public:
    virtual ~ContentProvider(){};
    virtual void init() = 0;
    virtual bool isEOData() const = 0;
    virtual long size(bool useCachedValue = true) = 0;
    virtual bool write(std::vector<u_char> &buffer) = 0;
    virtual bool read(std::vector<u_char> &out, long count = 0) = 0;
};

class Encryptor{
private:
    std::shared_ptr<ContentProvider> _in;
    std::shared_ptr<ContentProvider> _out;
    std::shared_ptr<ContentProvider> _key;
    virtual bool validateKey(std::shared_ptr<ContentProvider> keyToSet);
    virtual bool checkLengthOfKey(long length) = 0;
    virtual bool encdec(EncAction action) = 0;
    virtual bool generateKey(std::vector<u_char> &key) = 0;
protected:
    void processKey(bool generateKey = false);
    std::shared_ptr<ContentProvider> getInCP();
    std::shared_ptr<ContentProvider> getOutCP();
    std::shared_ptr<ContentProvider> getKeyCP();
public:
    Encryptor(std::shared_ptr<ContentProvider> cpIn, std::shared_ptr<ContentProvider> cpOut, std::shared_ptr<ContentProvider> cpKey);
    void setCtx(std::shared_ptr<ContentProvider> cpIn, std::shared_ptr<ContentProvider> cpOut, std::shared_ptr<ContentProvider> cpKey);
    virtual ~Encryptor();
    virtual bool encrypt() = 0;
    virtual bool decrypt() = 0;
};

#endif