#include  "Analyzer.h"
#include <vector>
struct Function
{
  DWORD offset;
  DWORD size;
};

//"\x00\x80\x37\x01\x00\x00", "xxxxxx"
bool CompareData(PBYTE pbData, PBYTE bytePattern, const char* byteMask)
{
  for (; *byteMask; ++byteMask, ++pbData, ++bytePattern)
  {
    if (*byteMask == 'x' && *pbData != *bytePattern)
      return FALSE;
  }
  return (*byteMask) == NULL;
}

bool FindPattern(const PBYTE pbBuffer, DWORD dwLength,
    const char* bytePattern, const char* byteMask, DWORD& offset)
{
  for (DWORD i = offset; i < dwLength; i++)
  {
    if (CompareData(pbBuffer + i, (BYTE*)bytePattern, byteMask))
    {
      offset = i;
      return true;
    }
  }
  return false;
}

void FindFunctions(SectionInfo& info, std::vector<Function>& functions)
{
  DWORD offset = 0;
find:
  //Function Prologue: 55 8B EC
  //push ebp
  //mov ebp, esp
  if (FindPattern(info.data, info.header.SizeOfRawData, "\x55\x8B\xEC", "xxx", offset))
  {
    DWORD start = offset++;
    //Function Epilogue: 8B E5 5D C3
    //mov esp, ebp
    //pop ebp
    //ret
    if (FindPattern(info.data, info.header.SizeOfRawData, "\x8B\xE5\x5D\xC3", "xxxx", offset))
    {
      DWORD end = offset + 3;
      Function f;
      f.offset = start;
      f.size = end - start;
      functions.push_back(f);
      goto find;
    }
  }
}


int FixAntiDisassembler(SectionInfo& info, const Function& function)
{
  //90 87 C0 7C F7  90 7C
  //nop
  //xchg <reg>
  //jl offset
  //garbage byte

  DWORD offset = 0;
  PBYTE fnData = function.offset + info.data;
  //printf("Starting scan at %p, data=%p, offset=%d\n", fnData, info.data, function.offset);
  int patched = 0;
scan:
  if (FindPattern(fnData, function.size,
    "\x90\x87\xFF\x7C\xFF\xFF", "xx?x??", offset))
  {
    offset += 5;
    DWORD garbageOffset = offset + function.offset;
    DWORD vaddr = WIN32_PE_ENTRY + info.header.VirtualAddress + garbageOffset;
    info.data[garbageOffset] = 0x90; //replace with nop
    ++patched;
    //printf("Found garbage byte at: %X (offset=%X, size=%X)\n", vaddr, offset, function.size);
    goto scan;
  }
  return patched;
}

void Analyzer::PatchSafeDiscAntiDisassembler(SectionInfo& info)
{
  std::vector<Function> functions;
  FindFunctions(info, functions);
  printf("Found %d functions in %s section\n", functions.size(), info.name);
  for (const Function& f : functions)
  {
    DWORD rva = WIN32_PE_ENTRY + info.header.VirtualAddress + f.offset;
    int result = FixAntiDisassembler(info, f);
    printf("[%s] Analyzed %d garbage bytes in function at: %0X - %0X (size=%0X)\n",
      info.name, result, rva, rva + f.size, f.size);
  }
}