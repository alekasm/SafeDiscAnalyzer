#pragma once
#include <Windows.h>
#include <string>
#include <vector>

static const DWORD WIN32_PE_ENTRY = 0x400000;
struct SectionInfo {
  SectionInfo(const char* name, const char* copy, BOOL decryptedExec = FALSE) : 
    name(name), copy(copy)
  {
    ZeroMemory(&header, sizeof(IMAGE_SECTION_HEADER));
  }
  SectionInfo(const char* name, BOOL decryptedExec = FALSE) : 
    name(name)
  {
    ZeroMemory(&header, sizeof(IMAGE_SECTION_HEADER));
  }
  SectionInfo()
  {
    ZeroMemory(&header, sizeof(IMAGE_SECTION_HEADER));
  }
  const char* name = NULL;
  const char* copy = NULL;
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
    SectionInfo(".text", ".tex2", TRUE), SectionInfo(".txt2", ".txt3", TRUE),
    SectionInfo(".txt"), SectionInfo(".data"), SectionInfo(".reloc")
  };
};

