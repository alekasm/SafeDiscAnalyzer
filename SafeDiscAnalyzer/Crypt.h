#pragma once
#include "PELoader.h"
uint32_t CreateNextDecryptionSkewFromText(PELoader& loader);
void Decrypt(PELoader& loader, uint32_t showOffset, uint32_t showSize);