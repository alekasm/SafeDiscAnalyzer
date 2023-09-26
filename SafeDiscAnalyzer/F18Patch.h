#pragma once
#include "PELoader.h"
struct Patch
{
  const char* section;
  uint32_t vaddress;
  PBYTE pByte;
};

void ApplyF18Patches(std::vector<SectionInfo>&);
void Decrypt(SectionInfo& info_txt, SectionInfo& info_txt2, unsigned int offset);