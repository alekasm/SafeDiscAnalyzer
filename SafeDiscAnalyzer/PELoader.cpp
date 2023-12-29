#include "PELoader.h"

void PELoader::Destroy()
{
  SectionMap::iterator it = sectionMap.begin();
  for (; it != sectionMap.end(); ++it)
  {
    if (it->second.data != NULL)
    {
      delete it->second.data;
      it->second.data = NULL;
    }
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

bool WriteData(HANDLE hFile, IMAGE_SECTION_HEADER header, PBYTE data)
{
  DWORD dwPtr = SetFilePointer(hFile, header.PointerToRawData, NULL, FILE_BEGIN);
  if (dwPtr == INVALID_SET_FILE_POINTER) // Test for failure
  {
    printf("Failed to SetFilePointer: %d\n", GetLastError());
    CloseHandle(hFile);
    return false;
  }
  DWORD bytesWritten;
  if (!WriteFile(hFile, data, header.SizeOfRawData, &bytesWritten, NULL))
  {
    printf("Failed to WriteFile: %d\n", GetLastError());
    return false;
  }
  return true;
}

DWORD align(DWORD addr, DWORD align)
{
  return (addr + align) - (addr % align);
}

DWORD PELoader::WriteDuplicatePEPatch(HANDLE hFile, PIMAGE_NT_HEADERS NT)
{
  //This is some actual Frankenstein stuff.
  //The relocation table which used for decryption is fine for modification in the
  //executable where the image base is at the desired location - not so much for 
  //DPLAYERX.DLL where the relocation table is needed.

  //What needed to happen was allowing the valid PE Header to load with the real
  //relocation table, then having a duplicate PE pointing to the modified relocation
  //table.

  //Solution 1 was to add the duplicate PE header to the end of the file, and then
  //redirect the offset there. Unfortunately for the read mode they end up not opening
  //a file handle, but instead use the virtual memory - meaning the new PE won't get mapped

  //Solution 2 was to once again abuse the free 16 section space along with the DOS Stub
  //to create more for a new PE header right next to the original. The original PE with
  //all section info is pushed right against the first section. The modified PE starts
  //at the DOS Stub.

  IMAGE_NT_HEADERS ntDuplicate;
  memcpy(&ntDuplicate, NT, sizeof(IMAGE_NT_HEADERS));
  DWORD relo2VAddress = sectionMap.at(RELO2).header.VirtualAddress;
  ntDuplicate.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = relo2VAddress;

  //TODO: NumberOfSections not reporting correct amount
  //DWORD sectionSize = NT->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
  DWORD sectionCount = 11;
  DWORD sectionSize = sectionCount * sizeof(IMAGE_SECTION_HEADER);
  DWORD maxSectionSize = 16 * sizeof(IMAGE_SECTION_HEADER);
  DWORD sectionOffset = maxSectionSize - sectionSize;
  DWORD peHeaderSize = sectionSize + sizeof(IMAGE_NT_HEADERS);
  printf("Size of total PE Header is: 0x%X (%d sections) which can be moved 0x%X bytes\n", peHeaderSize, NT->FileHeader.NumberOfSections, sectionOffset);

  DWORD dw;
  DWORD newPEOffset = 0x80 + sectionOffset;
  PBYTE peHeader = new BYTE[peHeaderSize];
  SetFilePointer(hFile, 0x80, NULL, FILE_BEGIN);
  ReadFile(hFile, peHeader, peHeaderSize, &dw, NULL);
  DWORD newAddr = SetFilePointer(hFile, newPEOffset, NULL, FILE_BEGIN);
  WriteFile(hFile, peHeader, peHeaderSize, &dw, NULL);
  SetFilePointer(hFile, 0x3C, NULL, FILE_BEGIN);
  WriteFile(hFile, &newAddr, sizeof(DWORD), &dw, NULL);


  DWORD ntDuplicatePtr = SetFilePointer(hFile, 0x40, NULL, FILE_BEGIN);
  if (ntDuplicatePtr == INVALID_SET_FILE_POINTER) // Test for failure
  {
    printf("Failed to SetFilePointer: %d\n", GetLastError());
    CloseHandle(hFile);
    return false;
  } 
  if (!WriteFile(hFile, &ntDuplicate, sizeof(IMAGE_NT_HEADERS), &dw, NULL))
  {
    printf("Failed to write duplicate NT header\n");
  }

  //0x3C is the usual pointer to PE header, using 0x38 instead and patching
  //functions later
  SetFilePointer(hFile, 0x38, NULL, FILE_BEGIN);
  WriteFile(hFile, &ntDuplicatePtr, sizeof(DWORD), &dw, NULL);

  printf("Wrote new PE Header at 0x%X, using new relocation at: 0x%X\n",
    ntDuplicatePtr, relo2VAddress);
  return ntDuplicatePtr;
}


bool PELoader::UpdateRelocationTable(PIMAGE_OPTIONAL_HEADER OH)
{
  SectionInfo& info_reloc = sectionMap.at(SectionType::RELO2);
  SectionInfo& info_text = sectionMap.at(SectionType::TEXT);
  uint32_t VirtualSize = info_text.header.Misc.VirtualSize;
  uint32_t VirtualAddressCopy = info_text.VirtualAddressCopy - GetImageBase();
  uint32_t VirtualAddressScan = info_text.VirtualAddress - GetImageBase();
  uint32_t table_offset = 0;
  uint32_t table_offset_iter = 0;
  bool found_entry = false;

  while (table_offset_iter < info_reloc.header.SizeOfRawData)
  {
    uint32_t VirtualAddress = 0;
    uint32_t EntrySize = 0;
    memcpy(&VirtualAddress, &info_reloc.data[table_offset_iter], 4);
    memcpy(&EntrySize, &info_reloc.data[table_offset_iter + 4], 4);

    if (VirtualAddress == VirtualAddressScan)
    {
      table_offset = table_offset_iter;
      printf("Found original .text relocation at 0x%X\n",
        table_offset + info_reloc.header.PointerToRawData);
      found_entry = true;
      break;
    }
    table_offset_iter += EntrySize;
  }

  if (!found_entry)
  {
    printf("Failed to find relocation entry for .text starting at 0x%X\n", VirtualAddressScan);
    return false;
  }

  const uint32_t OldTableSize = OH->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
  uint32_t next_table_offset = OldTableSize;
  PBYTE extended_copy = new BYTE[info_reloc.header.SizeOfRawData * 2];
  memset(extended_copy, 0, info_reloc.header.SizeOfRawData);
  memcpy(extended_copy, info_reloc.data, OldTableSize);

  printf("Start of duplicate table at 0x%X\n",
    next_table_offset + info_reloc.header.PointerToRawData);
  memset(&info_reloc.data[next_table_offset], 0, info_reloc.header.SizeOfRawData - next_table_offset);

  int32_t vsize = VirtualSize;
  uint32_t entry_va = 0;
  uint32_t entry_size = 0;
  uint32_t size_added = 0;
  unsigned int va_override = VirtualAddressCopy;
  uint32_t total_offset = 0;
  uint32_t last_va = 0;
  while (vsize > 0)
  {
    memcpy(&entry_va, &info_reloc.data[table_offset], 4);
    memcpy(&entry_size, &info_reloc.data[table_offset + 4], 4);
    uint32_t data_size = 0;

    //relocation tables can skip over pages
    if (last_va > 0)
      data_size = entry_va - last_va;
    last_va = entry_va;
    va_override += data_size;

    memcpy(&extended_copy[next_table_offset], &info_reloc.data[table_offset], entry_size);
    memcpy(&extended_copy[next_table_offset], &va_override, 4);
    size_added += entry_size;

    printf("Copying data from 0x%X -> 0x%X\n",
      table_offset + info_reloc.header.PointerToRawData,
      next_table_offset + info_reloc.header.PointerToRawData);

    printf("Updating relocation at 0x%X (0x%X): 0x%X -> 0x%X\n",
      table_offset,
      table_offset + info_reloc.header.PointerToRawData,
      entry_va, va_override);

    RelocationData data;
    data.size = entry_size - 8;
    data.offset = table_offset;
    data.end_offset = table_offset + entry_size;
    data.entry = entry_va;
    textCopyRelocations.push_back(data);

    vsize -= data_size > 0 ? data_size : 0x1000;
    table_offset += entry_size;
    next_table_offset += entry_size;
    total_offset += entry_size;
  }

  uint32_t NewTableSize = OldTableSize + size_added;
  PBYTE new_table = new BYTE[NewTableSize];
  memset(new_table, 0, NewTableSize);
  memcpy(new_table, extended_copy, NewTableSize);
  delete[] extended_copy;
  extended_copy = nullptr;

  delete info_reloc.data;
  info_reloc.data = new_table;

  OH->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = NewTableSize;
  printf("Extended .reloc table size from 0x%X -> 0x%X\n", OldTableSize,
    OH->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
 
  if (NewTableSize > info_reloc.header.SizeOfRawData)
  {
    DWORD oldSize = info_reloc.header.SizeOfRawData;
    info_reloc.header.SizeOfRawData = align(NewTableSize, OH->FileAlignment);
    printf("Increased .reloc SizeOfRawData: 0x%X -> 0x%X\n",
      oldSize, info_reloc.header.SizeOfRawData);
    DWORD rawDifference = info_reloc.header.SizeOfRawData - oldSize;
    OH->SizeOfImage = OH->SizeOfImage + rawDifference;
  }

  if (NewTableSize > info_reloc.header.Misc.VirtualSize)
  {
    DWORD oldSize = info_reloc.header.Misc.VirtualSize;
    info_reloc.header.Misc.VirtualSize = align(NewTableSize, OH->SectionAlignment);
    printf("Increased .reloc VirtualSize: 0x%X -> 0x%X\n",
      oldSize, info_reloc.header.Misc.VirtualSize);
  }

  return true;
}

DWORD PELoader::ExtendRelocationTable(HANDLE hFile, PIMAGE_NT_HEADERS NT)
{
  //SectionInfo& info_reloc = sectionMap.find(SectionType::RELO2)->second;
  SectionInfo& info_reloc = sectionMap.at(RELO2);
  DWORD relo2VAddress = info_reloc.header.VirtualAddress;
  int relo2Index = info_reloc.index;

  PIMAGE_FILE_HEADER FH = &NT->FileHeader;
  PIMAGE_OPTIONAL_HEADER OH = &NT->OptionalHeader;
  PIMAGE_SECTION_HEADER SH = (PIMAGE_SECTION_HEADER)((PBYTE)OH + FH->SizeOfOptionalHeader);

  //Update OptionalHeader entry
  DWORD osize = OH->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
  printf("Moving .reloc from 0x%X -> 0x%X\n",
    OH->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress,
    relo2VAddress);
  OH->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = relo2VAddress;
  UpdateRelocationTable(OH);
  SH[relo2Index].Misc.VirtualSize = info_reloc.header.Misc.VirtualSize;
  SH[relo2Index].SizeOfRawData = info_reloc.header.SizeOfRawData;

  printf("Duplicated relocation table with size 0x%X at 0x%X -> 0x%X\n",
    osize,
    SH[relo2Index].PointerToRawData,
    SH[relo2Index].PointerToRawData + osize);

  printf("Updated %s: VA=%0X,RVA=%0X,VSize=%0X,RDP=%0X,RSZ=%0X\n",
    info_reloc.name,
    SH[relo2Index].VirtualAddress, SH[relo2Index].VirtualAddress + imageBase,
    SH[relo2Index].Misc.VirtualSize,
    SH[relo2Index].PointerToRawData,
    SH[relo2Index].SizeOfRawData);
  return 1;
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

  SectionMap::const_iterator it = sectionMap.begin();
  for (; it != sectionMap.end(); ++it)
  {
    const SectionInfo& info = it->second;
    WriteData(hFile, info.header, info.data);
  }

  CloseHandle(hFile);
  printf("Wrote to file: %s\n", name.c_str());
  return true;
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
  IMAGE_DATA_DIRECTORY BaseRelocationTable = OH->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
  IMAGE_DATA_DIRECTORY ImportAddressTable = OH->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
  IMAGE_DATA_DIRECTORY ImportTable = OH->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
  printf("Base Relocation Table: 0x%X (size=0x%X)\n",
    BaseRelocationTable.VirtualAddress,
    BaseRelocationTable.Size);
  printf("Import Address Table: 0x%X (size=0x%X)\n",
    ImportAddressTable.VirtualAddress,
    ImportAddressTable.Size);
  printf("Import Table: 0x%X (size=0x%X)\n",
    ImportTable.VirtualAddress,
    ImportTable.Size);

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
    printf("%s: VA=%0X,RVA=%0X,VSize=%0X,RDP=%0X,RSZ=%0X\n",
      name.c_str(),
      SH[i].VirtualAddress, SH[i].VirtualAddress + imageBase,
      SH[i].Misc.VirtualSize,
      SH[i].PointerToRawData,
      SH[i].SizeOfRawData);

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
      if (info.duplicate != SectionType::NONE)
      {
        SectionInfo infoCopy((const char*)SH[NewIndex].Name);
        infoCopy.header = SH[NewIndex];
        infoCopy.index = NewIndex;
        sectionMap.insert({ info.duplicate, infoCopy }); //no iterators are invalidated
      }

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
  }

  //WriteDuplicatePEPatch(hFile, NT);
  ExtendRelocationTable(hFile, NT);
  //Update with the new header info
  SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
  WriteFile(hFile, pByte, fileSize, &dw, NULL);
  CloseHandle(hFile);
  return true;
}