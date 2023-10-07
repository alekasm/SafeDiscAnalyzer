#pragma once
#include "PELoader.h"
#include "Analyzer.h"

void ApplyF18Patches(PELoader&, bool magic);
void Decrypt(SectionInfo& info_txt, SectionInfo& info_txt2, unsigned int offset);