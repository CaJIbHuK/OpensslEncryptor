#include "BaseEncryptor.h"

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

class AES256Encryptor:public Encryptor{
private:
    bool checkLengthOfKey(long length) override ;
    bool encdec(EncAction action) override;
    bool generateKey(std::vector<u_char> &key) override;
public:
    AES256Encryptor(ContentProvider *cpIn,
                    ContentProvider *cpOut,
                    ContentProvider *cpKey,
                    bool generateKey);
    bool encrypt();
    bool decrypt();
};

class DESEncryptor:public Encryptor{
private:
    bool checkLengthOfKey(long length) override;
    bool generateKey(std::vector<u_char> &key) override;
    void addPadding(std::vector<u_char> &block, int blockLength);
    void removePadding(std::vector<u_char> &block);
protected:
    bool encdec(EncAction action) override;
public:
    DESEncryptor(ContentProvider *cpIn,
                 ContentProvider *cpOut,
                 ContentProvider *cpKey,
                 bool generateKey);
    bool encrypt() override;
    bool decrypt() override;
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
                 bool generateKey);
    bool encrypt();
    bool decrypt();
};

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
    RC4Encryptor(ContentProvider *cpIn,
                 ContentProvider *cpOut,
                 ContentProvider *cpKey,
                 bool generateKey);
    bool encrypt();
    bool decrypt();
};


