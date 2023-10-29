#pragma once
#include <Windows.h>
#include <string>
#include <vector>
#include <unordered_map>

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
  uint32_t VirtualAddress = 0;
  uint32_t VirtualAddressCopy = 0;
  IMAGE_SECTION_HEADER header;
  BOOL initialized = FALSE;
};

enum SectionType { TEXT, TXT2, TXT, DATA, RELOC };
typedef std::unordered_map<SectionType, SectionInfo> SectionMap;
struct PELoader
{
  bool LoadPEFile(const char* filepath);
  bool PatchPEFile(const char* filepath);
  bool FoundAllSections();
  void Destroy();
  SectionMap& GetSectionMap() { return sectionMap; }
private:
  SectionMap sectionMap = {
    {TEXT, SectionInfo(".text", ".tex2", TRUE)},
    {TXT2,  SectionInfo(".txt2", ".txt3", TRUE)},
    {TXT, SectionInfo(".txt")},
    {DATA, SectionInfo(".data")},
    {RELOC, SectionInfo(".reloc")}
  };

};

