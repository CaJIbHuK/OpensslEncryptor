#ifndef DES_ENCRYPTOR
#define DES_ENCRYPTOR

#include "BaseEncryptor.h"
#include "ContentProviders.h"

class DESEncryptor:public Encryptor{
private:
    bool checkLengthOfKey(long length) override;
    bool generateKey(std::vector<u_char> &key) override;
    void addPadding(std::vector<u_char> &block, int blockLength);
    void removePadding(std::vector<u_char> &block);
protected:
    bool encdec(EncAction action) override;
public:
    DESEncryptor(std::shared_ptr<ContentProvider> cpIn,
                 std::shared_ptr<ContentProvider> cpOut,
                 std::shared_ptr<ContentProvider> cpKey,
                 bool generateKey);
    bool encrypt() override;
    bool decrypt() override;
};

class DDESEncryptor:public Encryptor{
private:
    bool checkLengthOfKey(long length) override;
    bool generateKey(std::vector<u_char> &key) override;
    void addPadding(std::vector<u_char> &block, int blockLength);
    void removePadding(std::vector<u_char> &block);
protected:
    bool encdec(EncAction action) override;
public:
    DDESEncryptor(std::shared_ptr<ContentProvider> cpIn,
                  std::shared_ptr<ContentProvider> cpOut,
                  std::shared_ptr<ContentProvider> cpKey,
                  bool generateKey);
    bool encrypt() override;
    bool decrypt() override;
};

#endif