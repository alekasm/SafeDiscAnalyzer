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

std::vector<uint32_t> Analyzer::FindSectionPattern(SectionInfo& info, const char* pattern, const char* mask)
{
  DWORD offset = 0;
  std::vector<uint32_t> results;
  find:
  if (FindPattern(info.data, info.header.SizeOfRawData, pattern, mask, offset))
  {
    uint32_t soffset = offset + info.header.VirtualAddress + 0x400000;
    results.push_back(soffset);
    offset++;
    goto find;
  }
  return results;
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

bool Analyzer::CreateMD5Hash(std::string filename, std::string& out_hash)
{
  DWORD cbHash = 16;
  HCRYPTHASH hHash = 0;
  HCRYPTPROV hProv = 0;
  BYTE rgbHash[16];
  CHAR rgbDigits[] = "0123456789abcdef";
  HANDLE hFile = CreateFileA(filename.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL,
    OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
  int v = GetLastError();
  printf("%d\n", v);

  if (hFile == INVALID_HANDLE_VALUE)
  {
    std::string error_message = "Failed to retrieve the MD5 Hash of the program:\n";
    error_message += "CreateFileW has an invalid handle.\n";
    printf("%s", error_message.c_str());
    return false;
  }

  CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
  CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash);

  BOOL bResult = FALSE;
  DWORD BUFSIZE = 4096;
  BYTE rgbFile[4096];
  DWORD cbRead = 0;
  while (bResult = ReadFile(hFile, rgbFile, BUFSIZE, &cbRead, NULL))
  {
    if (0 == cbRead)
      break;

    CryptHashData(hHash, rgbFile, cbRead, 0);
  }

  std::string md5_hash = "";
  if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
  {
    for (DWORD i = 0; i < cbHash; i++)
    {
      char buffer[3]; //buffer needs terminating null
      sprintf_s(buffer, 3, "%c%c", rgbDigits[rgbHash[i] >> 4], rgbDigits[rgbHash[i] & 0xf]);
      md5_hash.append(buffer);
    }
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    CloseHandle(hFile);
    out_hash = md5_hash;
    return true;
  }
  else
  {
    CloseHandle(hFile);
    std::string error_message = "Failed to retrieve the MD5 Hash of the program:\n";
    error_message += "CryptGetHashParam returned false.\n";
    printf("%s", error_message.c_str());
    return false;
  }
}
