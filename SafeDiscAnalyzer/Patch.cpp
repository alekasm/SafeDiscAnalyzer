#include "Patch.h"
#include "Util.h"

#define DEBUGGING_ENABLED
#define DEBUG_INTERMEDIATE_RELOCATION_SKEW
//42A9D8 = ReadProcessMemory
//42A9F0 = WriteProcessMemory
//42AA08 = VirtualProtect
//42AA18 = CreateProcessA
//42AA28 = CreateProcessW
//42AA38 = GetStartupInfoA
//42AA48 = GetStartupInfoW
//42AA58 = GetSystemTime
//42AA68 = TerminateProcess
//42AA80 = Sleep
//4292F0 = CLCD32.DLL
//429300 = CLC16.DLL
//429310 = SECDRV_SYS
//42A978 = ReadProcessMemory
//42A9A0 = WriteProcessMemory
//42A9B8 = VirtualProtect
//42AB50 = IsDebuggerPresent
//42AB80 = Ntdll
//42AB90 = NtQueryInformationProcess
//42AB00 = Kernel32.dll
//42AB40 = CreateFileA
//42AB10 = \\\\.\\SICE
//42AB30 = \\\\.\\NTICE

const char* sTrue = "true";
const char* sFalse = "false";

const char* sbool(bool b)
{
  return b ? sTrue : sFalse;
}

void data_StringPatch(PELoader& loader,  bool patch)
{
  SectionInfo& info = loader.GetSectionMap().at(SectionType::DATA);
  std::vector<uint32_t> txt2_offsets = Analyzer::FindSectionPattern(info, ".txt2\x00", "xxxxxx", loader.GetImageBase());
  std::vector<uint32_t> text_offsets = Analyzer::FindSectionPattern(info, ".text\x00", "xxxxxx", loader.GetImageBase());

  for (uint32_t offset : txt2_offsets)
  {
    printf("[.data] Found .txt2 at 0x%X, patching: %s\n", offset, sbool(patch));
    if (patch)
      memcpy(&info.data[offset - info.VirtualAddress], ".txt3", 6);
  }

  for (uint32_t offset : text_offsets)
  {
    printf("[.data] Found .text at 0x%X, patching: %s\n", offset, sbool(patch));
    if (patch)
      memcpy(&info.data[offset - info.VirtualAddress], ".tex2", 6);
  }
}

void txt2_drvmgtPatch(PELoader& loader,  bool patch)
{  
  //Prevents drvmgt.dll from loading and calling Setup
  //SafeDiscError(0x0B, 0x0A, 0x10)
  //Function: 0x422F90
  //Setup appears to load/interact with SECDRV.SYS
  //This driver can be viewed in WindowXP with "driverquery"
  //sc query Secdrv
  //sc stop Secdrv
  //sc delete Secdrv

  //First argument is 0xFA which means call Setup
  //The other functions don't appear to ever be called
  //Second argument is
  //Third argument is the drvmgt return result, which should equal 0x64 for success
  //according to F18.exe and drvmgt.dll

  //size_t sectionOffset = 0x4229F0 - TXT2_SECTION;
  SectionInfo& info = loader.GetSectionMap().at(SectionType::TXT2);
  std::vector<uint32_t> offsets = Analyzer::FindSectionPattern(info, 
    "\x55\x8B\xEC\x81\xEC\xA0\x02\x00\x00", "xxxxxxxxx", loader.GetImageBase());
  if (offsets.size() != 1)
  {
    printf("Expected to find one result for drvmgt\n");
    return;
  }
  printf("[.txt2] Found drvmgt at 0x%X, patching: %s\n", offsets.at(0), sbool(patch));
  if (!patch) return;
  size_t sectionOffset = offsets.at(0) - info.VirtualAddress;
  memcpy(&info.data[sectionOffset],
    "\x8B\x4D\x10"          //mov ecx, dword ptr [ebp + 0x10]
    "\xB8\x64\x00\x00\x00"  //mov eax, 0x64
    "\x89\x01"              //mov dword ptr [ecx], eax
    "\xB8\x01\x00\x00\x00"  //mov eax, 0x1
    "\xC3",                 //ret
    16);

  //sub_40F780 drive check needs to return 1 for true
}


void txt2_SecdrvVerificationPatch(PELoader& loader, bool patch)
{
  //SecdrvVerification is used by the initial decryption from text/txt2, then
  //again once the txt section is decrypted. This function takes in a message type
  //which is sent to the driver in arg0. This can be:
  //3C = GetDebugRegisterInfo
  //3D = GetIdtInfo
  //3E = SetupVerification

  //The return results are quite easy and are stored in an ioctl buffer.
  //GetDebugRegisterInfo returns dr7 which is 0x400
  //GetIdtInfo returns 0x2C8
  //SetupVerification returns 0x5278D11B

  //SecdrvVerification(int mtype, int, int, int* return, int);
  //The two parameters which matter are mtype and the return.
  //SecdrvVerification should return TRUE.
  //The out return value is used in various places like the "skew"
  SectionInfo& info = loader.GetSectionMap().at(SectionType::TXT2);
  std::vector<uint32_t> offsets = Analyzer::FindSectionPattern(info,
    "\x55\x8B\xEC\x83\xEC\x08\xE8", "xxxxxxx", loader.GetImageBase());
  if (offsets.size() != 1)
  {
    printf("Expected to find one result for SecdrvVerification\n");
    return;
  }
  printf("[.txt2] Found SecdrvVerification at 0x%X, patching: %s\n",offsets.at(0), sbool(patch));
  if (!patch) return;
  size_t sectionOffset = offsets.at(0) - info.VirtualAddress;
  //Complete re-write of the entire function
  //This has a similar flavor to SECDRV.SYS ProcessIoctl

  memcpy(&info.data[sectionOffset],
    "\x55"                            //push ebp
    "\x8B\xEC"                        //mov ebp, esp
    "\x83\xEC\x08"                    //sub esp, 0x8
    "\x51"                            //push ecx
    "\x52"                            //push edx
    "\x33\xC0"                        //xor eax, eax
    "\x8B\x55\x08"                    //mov edx, [ebp+0x8]
    "\x8B\x4D\x14"                    //mov ecx, [ebp+0x14]
    "\x83\xEA\x3C"                    //sub edx, 0x3C
    "\x74\x0E"                        //jz 0xE
    "\x4A"                            //dec edx
    "\x74\x13"                        //jz 0x13
    "\x4A"                            //dec edx
    "\x74\x18"                        //jz 18
    "\xC7\x01\x00\x00\x00\x00"        //mov [ecx], 0x0
    "\xEB\x17"                        //jmp 0x17
    "\xC7\x01\x00\x04\x00\x00"        //mov [ecx] 0x400
    "\xEB\x0E"                        //jmp 0x0E
    "\xC7\x01\xC8\x02\x00\x00"        //mov [ecx], 0x2C8
    "\xEB\x06"                        //jmp 0x06
    "\xC7\x01\x1B\xD1\x78\x52"        //mov [ecx], 0x5278D11B
    "\x40"                            //inc eax
    "\x5A"                            //pop edx
    "\x59"                            //pop ecx
    "\x8B\xE5"                        //mov esp, ebp
    "\x5D"                            //pop ebp
    "\xC3",                           //ret
    64);
}


/*
ProcessEnvironmentBlock
Thread 5B0 TEB
KUSER_SHARED_DATA = 7FFE0000
GetRandomGeneration returns this value in shared data
shared data inside of the TEB
KUSER_SHARED_DATA
*/


void txt2_BeingDebuggedPEBPatch(PELoader& loader,  bool patch)
{
  //Uses TIB fs:18 + 0x30 = PEB + 2 = BeingDebugged
  //TODO: There's actually another check for +0x20 in the larger executable
  //size_t sectionOffset = 0x42436A - TXT2_SECTION;
  SectionInfo& info = loader.GetSectionMap().at(SectionType::TXT2);
  std::vector<uint32_t> offsets = Analyzer::FindSectionPattern(info,
    "\x64\xA1\x18\x00\x00\x00\x8B\x48\x30", "xxxxxxxxx", loader.GetImageBase());
  if (offsets.size() != 1)
  {
    printf("Expected to find one result for BeingDebuggedPEB\n");
    return;
  }
  printf("[.txt2] Found BeingDebuggedPEB at 0x%X, patching: %s\n", offsets.at(0), sbool(patch));
  if (!patch) return;
  size_t sectionOffset = offsets.at(0) - info.VirtualAddress;
  memcpy(&info.data[sectionOffset],
    "\x33\xC0"                 //xor eax, eax
    "\x90\x90\x90\x90\x90"     //nop (5)
    "\x90\x90\x90\x90\x90"     //nop (5)
    "\x90",                    //nop
    13);
}

void txt2_CheckKernel32BreakpointPatch(PELoader& loader,  bool patch)
{
  //Simply jmp 4245A6->42468F. Goes over all functions in the Kernel32 export directory
  //to see if the first byte of any function has a 0xCC
}

void txt2_IsBeingDebuggedPatch(PELoader& loader,  bool patch)
{
  //4242A9 they decrypt "IsDebuggerPresent" and call from Kernel32.dll
  //size_t sectionOffset = 0x4242D4 - TXT2_SECTION;
  SectionInfo& info = loader.GetSectionMap().at(SectionType::TXT2);
  std::vector<uint32_t> offsets = Analyzer::FindSectionPattern(info,
    "\xFF\x55\xF0\x66\x89\x85\x4C\xFF\xFF\xFF", "xxxxxxxxxx", loader.GetImageBase());
  if (offsets.size() != 1)
  {
    printf("Expected to find one result for IsBeingDebugged\n");
    return;
  }
  printf("[.txt2] Found IsBeingDebugged at 0x%X, patching: %s\n", offsets.at(0), sbool(patch));
  if (!patch) return;
  size_t sectionOffset = offsets.at(0) - info.VirtualAddress;
  memcpy(&info.data[sectionOffset],
    "\x33\xC0"                 //xor eax, eax
    "\x90",                    //nop
    3);
}

void txt2_NTQueryProcessInformationPatch(PELoader& loader,  bool patch)
{
  //Function: 0x4239DF
  // 0x423C1B = CALL NtQueryInformationProcess
  //  - arg0:GetCurrentProcess()
  //  - arg1: 7, ProcessDebugPort
  //  - arg2: stack variable, out ProcessInformation
  //  - arg3: 4, ProcessInformationLength
  //  - arg4: 0, ReturnLength (optional)
  // 
  // 423C57 has checks for NTSTATUS and the return value for ProcessDebugPort
  // ignore these values and just assign 0 to thhe stack variable
  // 423C57: jmp 423C96
  //size_t sectionOffset = 0x423C57 - TXT2_SECTION;
  SectionInfo& info = loader.GetSectionMap().at(SectionType::TXT2);
  std::vector<uint32_t> offsets = Analyzer::FindSectionPattern(info,
    "\x83\xBD\x2C\xFF\xFF\xFF\x00", "xxxxxxx", loader.GetImageBase());
  if (offsets.size() != 1)
  {
    printf("Expected to find one result for NTQueryProcessInformation\n");
    return;
  }
  printf("[.txt2] Found NTQueryProcessInformation at 0x%X, patching: %s\n", offsets.at(0), sbool(patch));
  if (!patch) return;
  size_t sectionOffset = offsets.at(0) - info.VirtualAddress;
  memcpy(&info.data[sectionOffset],
    "\xEB\x3D"                 //jmp 0x423C96
    "\x90\x90\x90\x90\x90",     //nop (5), correction for debugging
    7);
}

void txt2_SoftICEDebuggerCheck(PELoader& loader,  bool patch)
{
  // 0x42AB10 = Encrypted \\\\.\\SICE (driver)
  // 0x42AB30 = Encrypted \\\\.\\NTICE (driver)
  
  //Checks to see if SoftICE debugger is running. Not really necessary 
  //to patch, but did so anyways. Takes the file handle result and stores 
  //it onto a stack variable, then copied back into the function argument.
  //You want this to be -1, ie CreateFile(\\\\.\\NTICE) fails.

  //size_t sectionOffset = 0x423DDF - TXT2_SECTION;
  SectionInfo& info = loader.GetSectionMap().at(SectionType::TXT2);
  std::vector<uint32_t> offsets = Analyzer::FindSectionPattern(info,
    "\x8B\x8D\x60\xFF\xFF\xFF\x51\xFF", "xxxxxxxx", loader.GetImageBase());
  if (offsets.size() != 1)
  {
    printf("Expected to find one result for SoftICEDebugger\n");
    return;
  }
  printf("[.txt2] Found SoftICEDebugger at 0x%X, patching: %s\n", offsets.at(0), sbool(patch));
  if (!patch) return;
  size_t sectionOffset = offsets.at(0) - 0x12 - info.VirtualAddress;
  memcpy(&info.data[sectionOffset],
    "\xB8\xFF\xFF\xFF\xFF"          //mov eax, 0xFFFFFFFF
    "\x89\x85\x38\xFF\xFF\xFF"     //mov dword ptr ss:[ebp-C8], eax ; kept segment selector
    "\x90\x90",                    //nop (2), correction for debugging
    13);
}

//Function: 0x4239DF
//SafeDiscError(0x04, 0x07, 0x10)
//This function has various strings that are decrypted
// 0x423C1B = CALL NtQueryInformationProcess
//  - arg0:GetCurrentProcess()
//  - arg1: 7, ProcessDebugPort
//  - arg2: stack variable, out ProcessInformation
//  - arg3: 4, ProcessInformationLength
//  - arg4: 0, ReturnLength (optional)


void text_ApplyFauxCDCheckPatch(PELoader& loader,  bool patch)
{
  //The return result doesn't appear to be used, and nothing
  //interesting happens within the function itself besides
  //checking. This could be a purposeful trap.
  //size_t sectionOffset = 0x40F720 - TEXT_SECTION;
  SectionInfo& info = loader.GetSectionMap().at(SectionType::TEXT);
  std::vector<uint32_t> offsets = Analyzer::FindSectionPattern(info,
    "\x81\xEC\x04\x01\x00\x00\x8D\x44\x24\x00", "xxxxxxxxxx", loader.GetImageBase());
  if (offsets.size() != 1)
  {
    printf("Expected to find one result for FauxCDCheck\n");
    return;
  }
  printf("[.text] Found FauxCDCheck at 0x%X, patching: %s\n", offsets.at(0), sbool(patch));
  if (!patch) return;
  size_t sectionOffset = offsets.at(0) - info.VirtualAddress;
  memcpy(&info.data[sectionOffset],
    "\x66\xB8\x01\x00" //mov ax, 1
    "\xC3",            //ret
    5);
}

void txt2_ApplyInterruptDebugPatch(PELoader& loader,  bool patch)
{
  //0x424F90 function (HardwareDebugTrap) attempts to call "int 0x1"
  //which should result in an exception of 0xC0000005. If a debugger is present,
  //then this is exception is instead passed to the debugger and it won't enter
  //the exception handler.
  //TODO: This does not appear in the larger executable...
  //size_t sectionOffset = 0x424D69 - TXT2_SECTION;
  SectionInfo& info = loader.GetSectionMap().at(SectionType::TXT2);
  std::vector<uint32_t> offsets = Analyzer::FindSectionPattern(info,
    "\xC7\x05\x00\x00\x00\x00\xFF\x00\x00\x00\xE8", "xx????xxxxx", loader.GetImageBase());
  if (offsets.size() != 1)
  {
    printf("Expected to find one result for InterruptDebug\n");
    return;
  }
  printf("[.txt2] Found InterruptDebug at 0x%X, patching: %s\n", offsets.at(0), sbool(patch));
  if (!patch) return;
  size_t sectionOffset = offsets.at(0) - info.VirtualAddress;
  int dvalue;
  memcpy(&dvalue, &info.data[sectionOffset + 2], 4);
  //printf("InterruptDebug global variable at 0x%X\n", dvalue);
  memcpy(&info.data[sectionOffset],
    "\xC7\x05\x00\x00\x00\x00\x05\x00\x00\xC0" //mov dword ptr ds:[0x0042EC28], 0xC0000005
    "\x90\x90\x90\x90\x90",                    //nop (5) remove interrupt exception test
    15);
  memcpy(&info.data[sectionOffset + 2] , &dvalue, 4);
}


bool ApplyPatches(PELoader& loader)
{
  data_StringPatch(loader, true);
  txt2_IsBeingDebuggedPatch(loader, true);
  txt2_BeingDebuggedPEBPatch(loader, true);
  txt2_CheckKernel32BreakpointPatch(loader, true);
  txt2_ApplyInterruptDebugPatch(loader, true);
  txt2_drvmgtPatch(loader, true);
  txt2_SoftICEDebuggerCheck(loader, true);
  txt2_NTQueryProcessInformationPatch(loader, true);
  txt2_SecdrvVerificationPatch(loader, true);

  //if (!UpdateRelocationTable(loader, nullptr)) return false;
  return true;
}


uint32_t CreateNextDecryptionSkewFromText(PELoader& loader)
{
  SectionInfo& info_reloc = loader.GetSectionMap().at(SectionType::RELO2);
  SectionInfo& info_text = loader.GetSectionMap().at(SectionType::TEX2);
  SectionInfo& info_txt = loader.GetSectionMap().at(SectionType::TXT);
  SectionInfo& info_txt2 = loader.GetSectionMap().at(SectionType::TXT2);
 

  std::vector<RelocationData> reloc_data = loader.GetTextCopyRelocations();
  if (reloc_data.empty())
  {
    printf("Failed to decrypt, relocation data is empty\n");
    return 0;
  }

  uint32_t NextSkew = 0;


  //NextSkew = 0;
  unsigned int size_data = info_text.header.SizeOfRawData;
  unsigned int text_index = 0;
  int reloc_index = 0;

  uint32_t reloc_entry = reloc_data.at(reloc_index).entry;
  uint32_t reloc_offset = reloc_data.at(reloc_index).offset;
  uint32_t virtual_address_entry = 0;
  memcpy(&virtual_address_entry, &info_reloc.data[reloc_offset], 4);
  if (virtual_address_entry != reloc_entry)
  {
    printf("Raw Data Pointer: 0x%X\n", info_reloc.header.PointerToRawData);
    return 0;
  }

  uint32_t reloc_table = reloc_offset + 8;
  unsigned int table_index = reloc_table;
  unsigned short last_index = 0;
  unsigned int size_data_iter = size_data;
  unsigned int text_offset = 0;
  bool last_index_override = false;
  bool page_skip = false;
  if (size_data_iter > 0x1000)
    size_data_iter = 0x1000;

  //its possible to skip over relocation chunks
  while (size_data > 0)
  {


    //Function:0x4136A0
    unsigned short index_entry;
    memcpy(&index_entry, &info_reloc.data[table_index], 2);
    unsigned short index_upper = index_entry >> 0xC;
    unsigned short next_index = index_entry & 0xFFF;
    unsigned int current_index = 0;
    unsigned int true_last_index = last_index;
    switch (index_upper)
    {
    case 1:
    case 2:
      current_index = last_index + 2;
      break;
    case 3:
    case 4:
    case 5:
      current_index = last_index + 4;
      break;
    default:
      current_index = last_index + 0;
    }
    unsigned int size_count = next_index;
    unsigned int text_index = 0;
    if (current_index == last_index)
      current_index += 4;
    if (last_index > 0 || last_index_override)
    {
      size_count = size_count - current_index;
      text_index = current_index;
      last_index_override = false;
    }
    else
    {
      text_index = 0;
    }
    text_index += text_offset;

    if (next_index == 0)
    {
      if (size_data - size_data_iter > 0)
      { //table switch condition
        uint32_t switch_current_index = last_index + 4;
        text_index += switch_current_index - current_index;
        current_index = switch_current_index;
      }
      size_count = ((size_data_iter - 1) - current_index) + 1;
    }

    if (page_skip)
    {
      page_skip = false;
      current_index = 0;
      size_count = 0x1000;
      next_index = 0;
      index_upper = 0;
      last_index = -1;
    }

#ifdef DEBUGGING_ENABLED
    printf("[0x%X] entry<0x%X,0x%X> Decrypting 0x%X with size of 0x%X, ending: 0x%X, last=0x%X, current = 0x%X\n",
      table_index + info_reloc.header.PointerToRawData,
      next_index, index_upper,
      current_index, size_count, next_index,
      last_index, current_index);
    fflush(stdout);
#endif

    if (last_index == 0 && next_index == 0)
    {
#ifdef DEBUGGING_ENABLED
      printf("Skipped - likely starting new page on zero offset\n");
      fflush(stdout);
#endif
      current_index = 0;
      table_index = table_index + 2;
      last_index_override = true;
      continue;
    }
    last_index = next_index;

    //bool last_decrypt = false;
    if (next_index == 0)
    {
      if (size_data - size_data_iter > 0)
      {
        uint32_t old_reloc_entry = reloc_entry;
        ++reloc_index;

        //Verification Part 1
        if (reloc_index >= reloc_data.size())
        {
          printf("Relocation data only has %ld entries, attempting to grab entry %ld\n",
            reloc_index, reloc_data.size());
          return 0;
        }

        //Verification Part 2
        reloc_entry = reloc_data.at(reloc_index).entry;
        reloc_offset = reloc_data.at(reloc_index).offset;
        virtual_address_entry = 0;
        memcpy(&virtual_address_entry, &info_reloc.data[reloc_offset], 4);
        fflush(stdout);
        if (virtual_address_entry != reloc_entry)
        {
          printf("RelocationData Entry: 0x%X, RelocationTable Entry: 0x%X\n",
            reloc_entry, virtual_address_entry);
          printf("Raw Data Pointer: 0x%X\n", info_reloc.header.PointerToRawData);
          fflush(stdout);
          return 0;
        }
        uint32_t size_difference = (reloc_entry - old_reloc_entry);
        
        if (size_difference > 0x1000)
        { //page skip still gets processed
          reloc_entry = old_reloc_entry + 0x1000;
          --reloc_index;
          reloc_offset = reloc_data.at(reloc_index).offset;
          page_skip = true;
        }
        size_data -= (reloc_entry - old_reloc_entry);

        reloc_table = reloc_offset + 8;
        #ifdef DEBUG_INTERMEDIATE_RELOCATION_SKEW
        printf("[%d] Switching to new table: 0x%X (File Offset=0x%X), Size Remaining: 0x%X\n",
          reloc_index, reloc_entry, reloc_offset + info_reloc.header.PointerToRawData, size_data);
        fflush(stdout);
        #endif
      }
      else
      {
        //last_decrypt = true;
        size_data = 0;
      }


      table_index = reloc_table;
      last_index = 0;
      unsigned int old_iter = size_data_iter;
      if (size_data > 0x1000)
        size_data_iter = 0x1000;
      else
        size_data_iter = size_data;


#ifdef DEBUGGING_ENABLED
      printf("size remaining: 0x%X, iter: 0x%X\n", size_data, size_data_iter);
      fflush(stdout);
#endif
      text_offset += old_iter;
    }
    else
    {
      table_index = table_index + 2;
    }

    if (size_count == 0)
    {
#ifdef DEBUGGING_ENABLED
      printf("Size is zero - skipping\n");
      fflush(stdout);
#endif
      continue;
    }

    unsigned int starting_val = 0xFD379AB1;
    for (unsigned int j = size_count; j > 0; j--)
    {
      unsigned int v1 = info_text.data[text_index++] & 0xFF;
      v1 = v1 * starting_val;
      NextSkew += v1;
      unsigned int v2 = starting_val * 0xA7753394;
      starting_val = v2 + (j - 1) + 0x3BC62BB2;
    }

#ifdef DEBUG_INTERMEDIATE_RELOCATION_SKEW
    printf("Next Skew: 0x%X\n", NextSkew);
    fflush(stdout);
#endif
  }

#ifdef DEBUG_INTERMEDIATE_RELOCATION_SKEW
  printf("Final decryption skew: 0x%X\n", NextSkew);
  fflush(stdout);
#endif
  return NextSkew;
}

//TODO: relocation patching now works, but we need to re-adjust 
//But the returned decryption does not with the table skips
void Decrypt(PELoader& loader, int showOffset, int showSize)
{
  SectionInfo& info_reloc = loader.GetSectionMap().at(SectionType::RELO2);
  SectionInfo& info_text = loader.GetSectionMap().at(SectionType::TEX2);
  SectionInfo& info_txt = loader.GetSectionMap().at(SectionType::TXT);
  SectionInfo& info_txt2 = loader.GetSectionMap().at(SectionType::TXT2);

  if (showOffset + showSize > info_txt.header.Misc.VirtualSize)
  {
    unsigned long vaddr = loader.GetImageBase() + info_txt.header.VirtualAddress;
    printf("Decryption 0x%08X - 0x%08X is outside of .txt section 0x%08X - 0x%08X\n",
      vaddr + showOffset, vaddr + showOffset + showSize,
      vaddr, vaddr + info_txt.header.Misc.VirtualSize);
    return;
  }

  std::vector<RelocationData> reloc_data = loader.GetTextCopyRelocations();
  if (reloc_data.empty())
  {
    printf("Failed to decrypt, relocation data is empty\n");
    return;
  } 

  //txt section is the encrypted data that needs to be decrypted.
  //First pass prepares the encrypted txt section, xor with a rolling key - 8 bytes
  //The second pass xors with the txt2 section, and uses the secdrv kernel key every 16 bytes
  //Third pass will update the skew value as a result from the text section
  //Can verify this in .rdata +C, + 10 - consistent at least across Jane's F18
  const int DECRYPTION_SIZE = 0x20; //pre-defined rdata:00428010
  const int DECRYPTION_VALUE = 0x9E3779B9; //pre-defined rdata:0042800C
  const int DECRYPTION_VALUE_START = DECRYPTION_VALUE << 5; // 0xC6EF3720
  const char encrypted_string[16] = {
    0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8,
    0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF
  };

  const unsigned int string_val0 = *((int*)&encrypted_string[0x0]); //0x03020100
  const unsigned int string_val4 = *((int*)&encrypted_string[0x4]); //0x07060504
  const unsigned int string_val8 = *((int*)&encrypted_string[0x8]); //0x0B0A0908
  const unsigned int string_valC = *((int*)&encrypted_string[0xC]); //0x0C0D0E0F

  unsigned int decryption_key = DECRYPTION_VALUE_START;

  int index = 0;
  unsigned int NextSkew = CreateNextDecryptionSkewFromText(loader);
  unsigned int size = info_txt.header.SizeOfRawData;
  char* decrypt_buffer = new char[size];
  memset(decrypt_buffer, 0, size);

iter_firstpass:
  const unsigned int init_val1 = *((int*)&info_txt.data[index + 0]);
  const unsigned int init_val2 = *((int*)&info_txt.data[index + 4]);
  unsigned int encrypted_val1 = init_val1;
  unsigned int encrypted_val2 = init_val2;
  decryption_key = DECRYPTION_VALUE_START;

  //XORDecryptionOnBuffer - 0x421891
  for (int i = DECRYPTION_SIZE; i > 0; --i)
  {
    unsigned int ival1 = (encrypted_val1 << 4) + string_val8;
    ival1 = ival1 ^ (encrypted_val1 + decryption_key);
    unsigned int ival2 = (encrypted_val1 >> 5) + string_valC;
    ival1 = ival1 ^ ival2;

    encrypted_val2 = encrypted_val2 - ival1;

    unsigned int jval1 = (encrypted_val2 << 4) + string_val0;
    jval1 = jval1 ^ (encrypted_val2 + decryption_key);
    unsigned int jval2 = (encrypted_val2 >> 5) + string_val4;
    jval1 = jval1 ^ jval2;

    encrypted_val1 = encrypted_val1 - jval1;

    decryption_key -= DECRYPTION_VALUE;
  }
  memcpy(&decrypt_buffer[index + 0], &encrypted_val1, 4);
  memcpy(&decrypt_buffer[index + 4], &encrypted_val2, 4);

  index += 8;
  if (index < size)
    goto iter_firstpass;

  //0x421B38 - DecryptXORSections
  unsigned int decryption_skew = 0;
  for (int i = 0; i < size; ++i)
  {
    decrypt_buffer[i] ^= (decryption_skew >> 0);
    decrypt_buffer[i] ^= (decryption_skew >> 8);
    decrypt_buffer[i] ^= (decryption_skew >> 16);
    decrypt_buffer[i] ^= (decryption_skew >> 24);
    decrypt_buffer[i] ^= info_txt2.data[i];
    decryption_skew += decrypt_buffer[i] & 0xFF;
#ifdef DEBUGGING_ENABLED
    //printf("Decryption Skew: 0x%X\n", decryption_skew);
#endif
    if ((i + 1) % 0x10 == 0) //421DB9
      decryption_skew += 0x400; //dr7 result from secdrv driver
    if ((i + 1) % 0x1000 == 0)
    {
      decryption_skew += NextSkew;
    }
  } 
  unsigned long vaddr = loader.GetImageBase() + info_txt.header.VirtualAddress;
  printf("Decryption 0x%08X - 0x%08X:\n", vaddr + showOffset, vaddr + showOffset + showSize);
  for (unsigned int i = showOffset; i < (showOffset + showSize); ++i)
  {
    if (i % 0x10 == 0)
      printf("[%08X] ", vaddr + i);
    printf("%02X ", decrypt_buffer[i] & 0xFF);
    if ((i + 1) % 0x10 == 0)
      printf("\n");
  }
  printf("\n");
  delete[] decrypt_buffer;
}

