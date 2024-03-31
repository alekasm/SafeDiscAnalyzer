#pragma once
#include "PELoader.h"
#include "Analyzer.h"

bool ApplyPatches(PELoader&);
void CopyDecryptedSections(PELoader&);