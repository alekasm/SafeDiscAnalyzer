#pragma once
#include "PELoader.h"

enum CryptMode { ENCRYPT, DECRYPT };
uint32_t CreateNextDecryptionSkewFromText(PELoader& loader);
void Decrypt(PELoader& loader, uint32_t showOffset, uint32_t showSize, bool replace);
void CryptTest(PELoader&, uint32_t showOffset, uint32_t showSize, CryptMode);
void EncryptTest(char* buffer, unsigned int size);
void DecryptTest(char* buffer, unsigned int size);