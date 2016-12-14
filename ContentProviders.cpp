#include "ContentProviders.h"
#include "common.h"

//------------------------FILE PROVIDER-------------------------
FileProvider::FileProvider(std::string path, ContentDirection direction) {

    auto inMode = std::ios::in | std::ios::binary;
    auto outMode = std::ios::out | std::ios::binary | std::ios::trunc;
    auto inOutMode = std::ios::in | std::ios::out | std::ios::binary | std::ios::trunc;


    switch (direction) {
        case ContentDirection::In:
            this->_file.open(path, inMode);
            break;
        case ContentDirection::Out:
            this->_file.open(path, outMode);
            break;
        case ContentDirection::InOut:
            this->_file.open(path, inOutMode);
            break;
    }

    this->type = ContentProviderType::File;
}

void FileProvider::init() {
    this->cachedSize = 0;
    this->_file.clear();
    this->_file.seekg(0, std::ios::beg);
}

long FileProvider::size(bool useCachedValue) {
    if (this->cachedSize && useCachedValue) return this->cachedSize;

    auto currPos = this->_file.tellg();
    long length = 0;
    this->_file.seekg(0, this->_file.end);

    length = this->_file.tellg();
    this->cachedSize = length;

    this->_file.seekg(currPos);

    return length;
}

bool FileProvider::isEOData() const {
    return this->_file.eof();
}

bool FileProvider::read(std::vector<u_char> &out, long count) {
    out.clear();
    if (!this->_file.is_open()) return false;

    if (count == 0) count = this->size();

    char *buffer = new char[count];
    this->_file.read(buffer, count);
    if (this->_file.bad()) return false;

    std::streamsize amountOfReadBytes = this->_file.gcount();
    for (std::streamsize i = 0; i < amountOfReadBytes; ++i) {
        out.push_back((u_char)buffer[i]);
    }

    this->_file.peek();

    return true;
}

bool FileProvider::write(std::vector<u_char> &buffer) {
    if (!this->_file.is_open()) return false;
    this->_file.write((char*)buffer.data(), buffer.size());
    this->_file.flush();
    return !this->_file.bad();
}

//------------------------MEMORY PROVIDER-------------------------
MemoryProvider::MemoryProvider(std::vector<u_char> &initData) {
    this->memory.assign(initData.begin(), initData.end());
    this->type = ContentProviderType::Memory;
}

MemoryProvider::MemoryProvider() {
    this->type = ContentProviderType::Memory;
}

void MemoryProvider::init() {
    this->currIndex = 0;
    this->end = false;
}

long MemoryProvider::size(bool useCachedValue) {
    if (this->cachedSize && useCachedValue) return this->cachedSize;

    long length = this->memory.size();
    this->cachedSize = length;

    return length;
}

bool MemoryProvider::isEOData() const {
    return this->currIndex == this->memory.size();
}

bool MemoryProvider::read(std::vector<u_char> &out, long count) {
    out.clear();
    auto size = this->size();

    auto bytesToRead = (count == 0 || count + this->currIndex > size) ? size : this->currIndex + count;

    for (; this->currIndex < bytesToRead; this->currIndex++) {
        out.push_back(this->memory[this->currIndex]);
    }

    if (this->currIndex == size) this->end = true;

    return true;
}

bool MemoryProvider::write(std::vector<u_char> &buffer) {
    for(auto it = buffer.begin(); it < buffer.end(); it++)
        this->memory.push_back((*it));

    this->cachedSize = this->memory.size();

    return true;
}

