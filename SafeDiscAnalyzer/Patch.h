#pragma once
#include "PELoader.h"
#include "Analyzer.h"

bool ApplyPatches(PELoader&);
void Decrypt(PELoader&, int showOffset, int showSize);
uint32_t CreateNextDecryptionSkewFromText();