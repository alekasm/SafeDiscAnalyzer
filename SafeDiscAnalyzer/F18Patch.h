#pragma once
#include "PELoader.h"
#include "Analyzer.h"

void ApplyF18Patches(PELoader&, bool magic);
void Decrypt(PELoader&, int showOffset, int showSize);