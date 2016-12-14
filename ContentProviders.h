#ifndef CONTENT_PROVIDERS
#define CONTENT_PROVIDERS

#include "BaseEncryptor.h"
#include <fstream>

class FileProvider:public ContentProvider{
private:
    std::fstream _file;
public:
    FileProvider(std::string path, ContentDirection direction);
    virtual void init() override;
    virtual bool isEOData() const override ;
    long size(bool useCachedValue = true) override;
    bool write(std::vector<u_char> &buffer) override;
    bool read(std::vector<u_char> &out, long count = 0) override;
};

class MemoryProvider:public ContentProvider{
private:
    std::vector<u_char> memory;
    long currIndex = 0;
    bool end = false;
public:
    MemoryProvider(const std::vector<u_char> &initData);
    MemoryProvider();
    virtual void init() override;
    virtual bool isEOData() const override ;
    long size(bool useCachedValue = true) override;
    bool write(std::vector<u_char> &buffer) override;
    bool read(std::vector<u_char> &out, long count = 0) override;
};

#endif