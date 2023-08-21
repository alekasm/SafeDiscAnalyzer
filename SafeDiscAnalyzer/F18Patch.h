#pragma once
#include "PELoader.h"
struct Patch
{
  const char* section;
  uint32_t vaddress;
  PBYTE pByte;
};

void ApplyF18Patches(std::vector<SectionInfo>&);