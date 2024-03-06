#pragma once
#include "PELoader.h"

enum CryptMode { ENCRYPT, DECRYPT };
uint32_t CreateNextDecryptionSkewFromText(PELoader& loader);
//void Decrypt(PELoader& loader, uint32_t showOffset, uint32_t showSize, bool replace);
void Crypt(PELoader&, CryptMode);
bool CryptTest(PELoader&);
void PrintTxtSection(PELoader&, uint32_t showOffset, uint32_t showSize);