#pragma once
#include <Windows.h>
#include <unordered_map>
#include "PELoader.h"


struct Analyzer
{
  static void PatchSafeDiscAntiDisassembler(PELoader& loader, SectionType type);
  static bool CreateMD5Hash(std::string filename, std::string& out_hash);
  static std::vector<uint32_t> FindSectionPattern(SectionInfo&, const char* pattern, const char* mask, DWORD vAddress);
};