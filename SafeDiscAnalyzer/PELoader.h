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
  SectionInfo()
  {
    ZeroMemory(&header, sizeof(IMAGE_SECTION_HEADER));
  }
  const char* name = NULL;
  PBYTE data = NULL;
  uint32_t VirtualAddress;
  IMAGE_SECTION_HEADER header;
  BOOL initialized = FALSE;

};

struct PELoader
{
  bool LoadPEFile(const char* filepath);
  bool PatchPEFile(const char* filepath);
  bool GetSectionInfo(std::string name, SectionInfo* out);
  std::vector<SectionInfo>& GetSections() { return sections; }
private:
  std::vector<SectionInfo> sections = {
    SectionInfo(".text"), SectionInfo(".txt2"),
    SectionInfo(".txt"), SectionInfo(".data")
  };
};

