#pragma once
#include "PELoader.h"
#include "Analyzer.h"

void ApplyPatches(PELoader&, bool magic);
void Decrypt(PELoader&, int showOffset, int showSize);