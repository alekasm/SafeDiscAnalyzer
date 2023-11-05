#include "PELoader.h"

void PELoader::Destroy()
{
  SectionMap::iterator it = sectionMap.begin();
  for (; it != sectionMap.end(); ++it)
  {
    delete it->second.data;
  }
}

bool PELoader::FoundAllSections()
{
  SectionMap::const_iterator it = sectionMap.begin();
  bool found_all = true;
  for (; it != sectionMap.end(); ++it)
  {
    if (!it->second.initialized)
    {
      printf("Failed to find %s section\n", it->second.name);
      found_all = false;
    }
  }
  return found_all;
}

bool PELoader::PatchPEFile(const char* filepath)
{
  std::string name(filepath);
  name.append(".patch");

  HANDLE hFile = CreateFile(name.c_str(), GENERIC_READ | GENERIC_WRITE,
    0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (hFile == INVALID_HANDLE_VALUE)
  {
    printf("Failed to CreateFile %s with error code: %d\n", name.c_str(), GetLastError());
    return false;
  }

  SectionMap::const_iterator it= sectionMap.begin();
  for (; it != sectionMap.end(); ++it)
  {
    const SectionInfo& info = it->second;
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


DWORD align(DWORD addr, DWORD align)
{
  return (addr + align) - (addr % align);
}

bool PELoader::LoadPEFile(const char* filepath)
{
  std::string filepath2(filepath);
  filepath2.append(".patch");

  if (!CopyFile(filepath, filepath2.c_str(), FALSE))
  {
    printf("Error copying %s to %s, Error: %d\n", filepath, filepath2.c_str(), GetLastError());
    return false;
  }

  HANDLE hFile = CreateFile(filepath2.c_str(), GENERIC_READ | GENERIC_WRITE,
    0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (hFile == INVALID_HANDLE_VALUE)
  {
    printf("Failed to CreateFile %s with error code: %d\n", filepath, GetLastError());
    return false;
  }

  DWORD fileSize = GetFileSize(hFile, NULL);
  DWORD EndOfFile = fileSize;
  BYTE* pByte = new BYTE[fileSize];
  
  DWORD dw;
  if (!ReadFile(hFile, pByte, fileSize, &dw, NULL))
  {
    printf("Failed to ReadFile %s with error code: %d\n", filepath, GetLastError());
    return false;
  }

  PIMAGE_DOS_HEADER DOS = (PIMAGE_DOS_HEADER)pByte;
  if (DOS->e_magic != IMAGE_DOS_SIGNATURE)
  {
    printf("File is missing DOS signature\n");
    return false;
  }
  
  PIMAGE_NT_HEADERS NT = (PIMAGE_NT_HEADERS)(pByte + DOS->e_lfanew);
  if (NT->Signature != IMAGE_NT_SIGNATURE)
  {
    printf("File is missing NT signature\n");
    return false;
  }

  PIMAGE_FILE_HEADER FH = &NT->FileHeader;
  PIMAGE_OPTIONAL_HEADER OH = &NT->OptionalHeader;
  printf("Image Base: 0x%X\n", OH->ImageBase);
  if (OH->ImageBase > 0)
    imageBase = OH->ImageBase;
  IMAGE_DATA_DIRECTORY z = OH->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
  if (OH->Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
  {
    printf("File is missing Optional Header signature\n");
    return false;
  }
  PIMAGE_SECTION_HEADER SH = (PIMAGE_SECTION_HEADER)((PBYTE)OH + FH->SizeOfOptionalHeader);

  //The offset of the first Section Header is 0x178, and if the PE is standard the first section
  //starts at offset 0x400 - each section header is 0x28 bytes. This means that there can be
  //16 section headers without having to move the actual sections - a problem with adding sections
  //on ELFs.

  printf("Total sections: %d\n", FH->NumberOfSections);
  for (WORD i = 0; i < FH->NumberOfSections; ++i)
  {
    std::string name(reinterpret_cast<char const*>(SH[i].Name));
    printf("%s: VA=%0X,RVA=%0X,VSize=%0X,RDP=%0X,RSZ=%0X,VSZ=%0X\n",
      name.c_str(),
      SH[i].VirtualAddress, SH[i].VirtualAddress + imageBase,
      SH[i].Misc.VirtualSize,
      SH[i].PointerToRawData,
      SH[i].SizeOfRawData,
      SH[i].Misc.VirtualSize);

    SectionMap::iterator it_copy = sectionMap.begin();
    for (; it_copy != sectionMap.end(); ++it_copy)
    {
      const char* section_name = NULL;
      const char* section_copy = NULL;
      SectionInfo& info = it_copy->second;
      if (info.copy != NULL && name.compare(info.name) == 0)
      {
        section_name = info.name;
        section_copy = info.copy;
      }
      if (!section_copy)
        continue;
      //Make an assumption that the last entry is also the last virtually for data
      WORD EndIndex = FH->NumberOfSections - 1;
      WORD NewIndex = FH->NumberOfSections;
      ZeroMemory(&SH[NewIndex], sizeof(IMAGE_SECTION_HEADER));
      CopyMemory(&SH[NewIndex].Name, section_copy, 8);
      SH[NewIndex].Misc.VirtualSize = SH[i].Misc.VirtualSize;
      SH[NewIndex].VirtualAddress = align(SH[EndIndex].VirtualAddress + SH[EndIndex].Misc.VirtualSize, OH->SectionAlignment);
      SH[NewIndex].SizeOfRawData = SH[i].SizeOfRawData;
      SH[NewIndex].Characteristics = SH[i].Characteristics;
      SH[NewIndex].PointerToRawData = align(EndOfFile, OH->FileAlignment);

      OH->SizeOfImage = SH[NewIndex].VirtualAddress + SH[NewIndex].Misc.VirtualSize;
      FH->NumberOfSections++;
      EndOfFile = EndOfFile + SH[NewIndex].SizeOfRawData;

      //Update with the new header info
      SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
      WriteFile(hFile, pByte, fileSize, &dw, NULL);

      PBYTE buffer = new BYTE[SH[NewIndex].SizeOfRawData];
      ZeroMemory(buffer, SH[NewIndex].SizeOfRawData);
      DWORD bytesRead;

      printf("Copying %s (Offset: 0x%X, VA:0x%X) section to %s (Offset:0x%X, VA:0x%X)\n",
        SH[i].Name, SH[i].PointerToRawData, SH[i].VirtualAddress + imageBase,
        SH[NewIndex].Name, SH[NewIndex].PointerToRawData, SH[NewIndex].VirtualAddress + imageBase);
      it_copy->second.VirtualAddressCopy = SH[NewIndex].VirtualAddress + imageBase;

      SetFilePointer(hFile, SH[i].PointerToRawData, NULL, FILE_BEGIN);
      if (!ReadFile(hFile, buffer, SH[i].SizeOfRawData, &bytesRead, NULL))
      {
        printf("Error reading file: %d\n", GetLastError());
        return false;
      }

      SetFilePointer(hFile, SH[NewIndex].PointerToRawData, NULL, FILE_BEGIN);
      if (!WriteFile(hFile, buffer, SH[NewIndex].SizeOfRawData, &dw, NULL))
      {
        printf("Error writing file: %d\n", GetLastError());
        return false;
      }
      break;
    }
    
    SectionMap::iterator it = sectionMap.begin();
    for(; it != sectionMap.end(); ++it)
    {
      SectionInfo& info = it->second;
      if (name.compare(info.name) == 0)
      {
        IMAGE_SECTION_HEADER header;
        ZeroMemory(&header, sizeof(IMAGE_SECTION_HEADER));
        memcpy(&header, &SH[i], sizeof(IMAGE_SECTION_HEADER));
        info.VirtualAddress = header.VirtualAddress + imageBase;

        SetFilePointer(hFile, header.PointerToRawData, NULL, FILE_BEGIN);
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
    //delete pByte;
  }

  CloseHandle(hFile);
  return true;
}