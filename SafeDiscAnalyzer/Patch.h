#pragma once
#include "PELoader.h"
#include "Analyzer.h"

bool ApplyPatches(PELoader&, bool magic);
void Decrypt(PELoader&, int showOffset, int showSize);