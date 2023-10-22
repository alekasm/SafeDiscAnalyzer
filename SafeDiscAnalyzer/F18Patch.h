#pragma once
#include "PELoader.h"
#include "Analyzer.h"

void ApplyF18Patches(PELoader&, bool magic);
void Decrypt(SectionInfo& info_txt, SectionInfo& info_txt2, SectionInfo& info_text, SectionInfo& info_reloc, int showOffset, int showSize);