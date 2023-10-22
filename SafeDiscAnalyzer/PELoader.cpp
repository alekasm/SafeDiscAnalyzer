#include "PELoader.h"

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

bool PELoader::GetSectionInfo(std::string name, SectionInfo* out)
{
  for (SectionInfo& info : sections)
    if (name.compare(info.name) == 0)
    {
      out = &info;
      return true;
    }
  return false;
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
      SH[i].VirtualAddress, SH[i].VirtualAddress + WIN32_PE_ENTRY,
      SH[i].Misc.VirtualSize,
      SH[i].PointerToRawData,
      SH[i].SizeOfRawData,
      SH[i].Misc.VirtualSize);

    const char* section_name = NULL;
    const char* section_copy = NULL;
    for (SectionInfo& info : sections)
    {
      if (info.copy != NULL && name.compare(info.name) == 0)
      {
        section_name = info.name;
        section_copy = info.copy;
        break;
      }
    }
    
    if (section_copy)
    {
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
        SH[i].Name, SH[i].PointerToRawData, SH[i].VirtualAddress + WIN32_PE_ENTRY,
        SH[NewIndex].Name, SH[NewIndex].PointerToRawData, SH[NewIndex].VirtualAddress + WIN32_PE_ENTRY);

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
    }

    /*
    if (name.compare(".idata") == 0)
    {
      printf("Looking at idata section: 0x%X\n", SH[i].PointerToRawData);
      IMAGE_IMPORT_DESCRIPTOR Start = (IMAGE_IMPORT_DESCRIPTOR)pByte[SH[i].PointerToRawData];
      printf("Start Name: %s\n", Start->Name);
      printf("xyz: 0x%X\n", Start->OriginalFirstThunk);
    }
    */

    for (SectionInfo& info : sections)
    {
      if (name.compare(info.name) == 0)
      {
        IMAGE_SECTION_HEADER header;
        ZeroMemory(&header, sizeof(IMAGE_SECTION_HEADER));
        memcpy(&header, &SH[i], sizeof(IMAGE_SECTION_HEADER));
        info.VirtualAddress = header.VirtualAddress + WIN32_PE_ENTRY;

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