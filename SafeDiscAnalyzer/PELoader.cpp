#include "PELoader.h"

bool PELoader::PatchPEFile(const char* filepath, const std::vector<SectionInfo>& sections)
{
  std::string name(filepath);
  name.append(".patch");

  if (!CopyFile(filepath, name.c_str(), FALSE))
  {
    printf("Error copying %s to %s, Error: %d\n", filepath, name.c_str(), GetLastError());
    return false;
  }
  HANDLE hFile = CreateFile(name.c_str(), GENERIC_READ | GENERIC_WRITE,
    0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (hFile == INVALID_HANDLE_VALUE)
  {
    printf("Failed to CreateFile %s with error code: %d\n", name.c_str(), GetLastError());
    return false;
  }
  for (const SectionInfo& info : sections)
  {
    DWORD dwPtr = SetFilePointer(hFile, info.header.PointerToRawData, NULL, FILE_BEGIN);
    if (dwPtr == INVALID_SET_FILE_POINTER) // Test for failure
    {
      printf("Failed to SetFilePointer: %d\n", GetLastError());
      CloseHandle(hFile);
      return false;
    }
    DWORD bytesWritten;
    if (!WriteFile(hFile, info.data, info.header.SizeOfRawData, &bytesWritten, NULL))
    {
      printf("Failed to write to file %s with error: %d\n", name.c_str(), GetLastError());
      return false;
    }
  }
  CloseHandle(hFile);
  printf("Wrote to file: %s\n", name.c_str());
  return true;
}

bool PELoader::LoadPEFile(const char* filepath, std::vector<SectionInfo>& sections)
{
  HANDLE hFile = CreateFile(filepath, GENERIC_READ,
    0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (hFile == INVALID_HANDLE_VALUE)
  {
    printf("Failed to CreateFile %s with error code: %d\n", filepath, GetLastError());
    return false;
  }

  DWORD fileSize = GetFileSize(hFile, NULL);
  BYTE* pByte = new BYTE[fileSize];
  DWORD dw;
  if (!ReadFile(hFile, pByte, fileSize, &dw, NULL))
  {
    printf("Failed to ReadFile %s with error code: %d\n", filepath, GetLastError());
    return false;
  }

  PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)pByte;
  if (dos->e_magic != IMAGE_DOS_SIGNATURE)
  {
    printf("File is missing DOS signature\n");
    return false;
  }

  PIMAGE_FILE_HEADER FH = (PIMAGE_FILE_HEADER)(pByte + dos->e_lfanew + sizeof(DWORD));
  PIMAGE_OPTIONAL_HEADER OH = (PIMAGE_OPTIONAL_HEADER)(pByte + dos->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));
  PIMAGE_SECTION_HEADER SH = (PIMAGE_SECTION_HEADER)(pByte + dos->e_lfanew + sizeof(IMAGE_NT_HEADERS));

  printf("Total sections: %d\n", FH->NumberOfSections);

  for (WORD i = 0; i < FH->NumberOfSections; ++i)
  {
    std::string name(reinterpret_cast<char const*>(SH[i].Name));
    for (SectionInfo& info : sections)
    {
      if (name.compare(info.name) == 0)
      {
        IMAGE_SECTION_HEADER header;
        ZeroMemory(&header, sizeof(IMAGE_SECTION_HEADER));
        header = SH[i];
        //File Offset will be PointerToRawData (1D800)
        //Section Size will be SizeOfRawData (8200)
        printf("%s: VA=%0X,RVA=%0X,PA=%0X,RDP=%0X,RSZ=%0X,VSZ=%0X\n",
          name.c_str(),
          header.VirtualAddress, header.VirtualAddress + WIN32_PE_ENTRY,
          header.Misc.PhysicalAddress,
          header.PointerToRawData,
          header.SizeOfRawData,
          header.Misc.VirtualSize);

        DWORD dwPtr = SetFilePointer(hFile, header.PointerToRawData, NULL, FILE_BEGIN);
        if (dwPtr == INVALID_SET_FILE_POINTER) // Test for failure
        {
          printf("Failed to SetFilePointer: %d\n", GetLastError());
          CloseHandle(hFile);
          return false;
        }

        PBYTE buffer = new BYTE[header.SizeOfRawData];
        ZeroMemory(buffer, header.SizeOfRawData);
        DWORD bytesRead;
        if (!ReadFile(hFile, buffer, header.SizeOfRawData, &bytesRead, NULL) ||
          bytesRead != header.SizeOfRawData)
        {
          printf("Read %0X/%0X bytes, error: %d\n",
            bytesRead, header.SizeOfRawData, GetLastError());
          CloseHandle(hFile);
          return false;
        }
        info.data = buffer;
        info.header = header;
        info.initialized = TRUE;
        break;
      }
    }
  }

  CloseHandle(hFile);
  return true;
}