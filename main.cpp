#include "encFabric.h"


int main() {
    Encryptor* encryptor = EncryptorFabric::getEncryptor(EncType::OTP,
                                  ContentProviderType::File,
                                  "/home/zas/Programming/CPP/encFabric/aaa",
                                  ContentProviderType::File,
                                  "/home/zas/Programming/CPP/encFabric/ooo",
                                  ContentProviderType::File,
                                  "/home/zas/Programming/CPP/encFabric/key",
                                  true);
    encryptor->encrypt();
    return 0;
}