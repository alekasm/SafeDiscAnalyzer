#pragma once
#include <Windows.h>
#include <string>
#include <vector>
static const DWORD WIN32_PE_ENTRY = 0x400000;
struct SectionInfo {
  SectionInfo(const char* name) : name(name) 
  {
    ZeroMemory(&header, sizeof(IMAGE_SECTION_HEADER));
  }
  const char* name = NULL;
  PBYTE data = NULL;
  IMAGE_SECTION_HEADER header;
  BOOL initialized = FALSE;
};

struct PELoader
{
  bool LoadPEFile(const char* filepath, std::vector<SectionInfo>& info);
  bool PatchPEFile(const char* filepath, const std::vector<SectionInfo>& sections);
};

