#pragma once
#include "PELoader.h"
#include "Analyzer.h"

void ApplyF18Patches(PELoader&);
void Decrypt(SectionInfo& info_txt, SectionInfo& info_txt2, unsigned int offset);