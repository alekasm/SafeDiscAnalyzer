#pragma once
#include "PELoader.h"
#include "Analyzer.h"

bool ApplyPatches(PELoader&, bool);
void CopyDecryptedSections(PELoader&);