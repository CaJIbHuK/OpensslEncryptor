#include "encLib.h"


int main() {
    Encryptor* encryptor = EncryptorFabric::getFileEncryptor(EncType::OTP,
                                  "/home/zas/Programming/CPP/encFabric/aaa",
                                  "/home/zas/Programming/CPP/encFabric/ooo",
                                  "/home/zas/Programming/CPP/encFabric/key",
                                    true);
    encryptor->encrypt();

    Encryptor* decryptor = EncryptorFabric::getFileEncryptor(EncType::OTP,
                                                             "/home/zas/Programming/CPP/encFabric/ooo",
                                                             "/home/zas/Programming/CPP/encFabric/dec",
                                                             "/home/zas/Programming/CPP/encFabric/key");
    decryptor->decrypt();
    return 0;
}