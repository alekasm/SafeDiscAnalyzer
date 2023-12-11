#pragma once
#include <Windows.h>
#include <string>
#include <vector>
#include <unordered_map>

enum SectionType { NONE = 0, TEXT, TXT2, TXT, DATA, RELOC, RELO2, RDATA };

struct SectionInfo {
  SectionInfo(const char* name, const char* copy, SectionType duplicate = NONE) :
    name(name), copy(copy), duplicate(duplicate)
  {
  }
  SectionInfo(const char* name, SectionType duplicate = NONE) :
    name(name), duplicate(duplicate)
  { 
  }
  SectionInfo() : duplicate(NONE){}
  const char* name = NULL;
  const char* copy = NULL;
  PBYTE data = NULL;
  uint32_t VirtualAddress = 0;
  uint32_t VirtualAddressCopy = 0;
  IMAGE_SECTION_HEADER header = { 0 };
  BOOL initialized = FALSE;
  const SectionType duplicate;
  int index = -1;
};

struct RelocationData {
  uint32_t size;
  uint32_t offset;
  uint32_t end_offset;
  uint32_t entry;
};

typedef std::unordered_map<SectionType, SectionInfo> SectionMap;
struct PELoader
{
  bool LoadPEFile(const char* filepath);
  bool PatchPEFile(const char* filepath);
  bool FoundAllSections();
  void Destroy();
  DWORD GetImageBase() { return imageBase; }
  SectionMap& GetSectionMap() { return sectionMap; }
  std::vector<RelocationData> GetTextCopyRelocations() { return textCopyRelocations; }
private:
  DWORD WriteDuplicatePEPatch(HANDLE hFile, PIMAGE_NT_HEADERS NT);
  DWORD ExtendRelocationTable(HANDLE hFile, PIMAGE_NT_HEADERS NT);
  bool UpdateRelocationTable(PIMAGE_OPTIONAL_HEADER OH);
  const DWORD WIN32_PE_ENTRY = 0x400000;
  DWORD imageBase = WIN32_PE_ENTRY;
  SectionMap sectionMap = {
    {TEXT, SectionInfo(".text", ".tex2")},
    {TXT2,  SectionInfo(".txt2", ".txt3")},
    {TXT, SectionInfo(".txt")},
    {DATA, SectionInfo(".data")},
    {RDATA, SectionInfo(".rdata")},
    {RELOC, SectionInfo(".reloc", ".relo2", RELO2)}
  };
  std::vector<RelocationData> textCopyRelocations;
};

