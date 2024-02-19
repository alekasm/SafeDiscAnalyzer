#pragma once
#include "PELoader.h"
#include "Analyzer.h"

bool ApplyPatches(PELoader&);
void Decrypt(PELoader& loader, uint32_t showOffset, uint32_t showSize);