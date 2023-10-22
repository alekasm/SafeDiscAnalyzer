#include "F18Patch.h"

#define TXT2_SECTION 0x41F000
#define TEXT_SECTION 0x40C000
#define DATA_SECTION 0x429000

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

void data_StringPatch(SectionInfo& info)
{
  std::vector<uint32_t> offsets = Analyzer::FindSectionPattern(info, ".txt2\x00", "xxxxxx");
  if (offsets.size() != 3)
  {
    printf("Found %ld results for .txt2\n", offsets.size());
    return;
  }
  for (uint32_t offset : offsets)
  {
    printf("Found .txt2 at 0x%X\n", offset);
    memcpy(&info.data[offset - info.VirtualAddress], ".txt3", 6);
  }

  std::vector<uint32_t> offsets2 = Analyzer::FindSectionPattern(info, ".text\x00", "xxxxxx");
  if (offsets2.size() != 1)
  {
    printf("Found %ld results for .text\n", offsets2.size());
    return;
  }
  for (uint32_t offset : offsets2)
  {
    printf("Found .text at 0x%X\n", offset);
    memcpy(&info.data[offset - info.VirtualAddress], ".tex2", 6);
  }
}

void txt2_drvmgtPatch(SectionInfo& info)
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
  std::vector<uint32_t> offsets = Analyzer::FindSectionPattern(info, "\x55\x8B\xEC\x81\xEC\xA0\x02\x00\x00", "xxxxxxxxx");
  if (offsets.size() != 1)
  {
    printf("Expected to find one result for drvmgt\n");
    return;
  }
  printf("Found drvmgt at 0x%X\n", offsets.at(0));
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

void text_CanOpenSecdrvPatch(SectionInfo& info)
{
  //First calls CanOpenSecdrv then OpenSecdrv using the handle \\\\.\\Secdrv
  //This really doesn't do much besides take in some message then return a bool.

  //size_t sectionOffset = 0x4147A3 - TEXT_SECTION;
  std::vector<uint32_t> offsets = Analyzer::FindSectionPattern(info, "\x55\x8B\xEC\x51\xE8\x20\x00\x00\x00", "xxxxxxxxx");
  if (offsets.size() != 1)
  {
    printf("Expected to find one result for CanOpenSecdrv\n");
    return;
  }
  printf("Found CanOpenSecdrv at 0x%X\n", offsets.at(0));
  size_t sectionOffset = offsets.at(0) - info.VirtualAddress;
  memcpy(&info.data[sectionOffset],
    "\xB8\x01\x00\x00\x00"  //mov eax, 0x1
    "\xC3",                 //ret
    6);
}

void text_SecdrvProcessIoctlPatch(SectionInfo& info)
{
  //First calls CanOpenSecdrv then OpenSecdrv using the handle \\\\.\\Secdrv
  //This calls an ioctl with the following buffer (IoctlBuffer):
  //IoctlBuffer[0] = 1 (4 byte)
  //IoctlBuffer[4] = 3 (4 byte)
  //IoctlBuffer[8] = 0 (4 byte)
  //IoctlBuffer[C] = 3C(4 byte) <- control code, checked in secdrv.sys:ProcessIoctl
  //IoctlBuffer[10] = tickCount
  //IoctlBuffer[410] = 0 (4 byte)
  //IoctlBuffer[514] = status message, outBuffer
  //IoctlBuffer[520] = kernel time reported
  //size_t sectionOffset = 0x414818 - TEXT_SECTION;
  std::vector<uint32_t> offsets = Analyzer::FindSectionPattern(info, "\x55\x8B\xEC\x83\xEC\x0C\xE8\xA9\xFF\xFF\xFF", "xxxxxxxxxx");
  if (offsets.size() != 1)
  {
    printf("Expected to find one result for SecdrvProcessIoctl\n");
    return;
  }
  printf("Found SecdrvProcessIoctl at 0x%X\n", offsets.at(0));

  //We will use this function as free space to write code that will populate the IoctlBuffer with the expected
  //values. Luckily there's just a magic number - 0x400. The offset is at the outbuffer section + 410/414 which ends up
  //being buffer+924/928h
  size_t sectionOffset = offsets.at(0) - info.VirtualAddress;
  int IoctlBuffer;
  memcpy(&IoctlBuffer, &info.data[sectionOffset + 0x2C], 4);
  memcpy(&info.data[sectionOffset],
    "\x8B\x0D\x00\x00\x00\x00"   //mov ecx, [IoctlBuffer]
    "\x81\xC1\x24\x09\x00\x00"   //add ecx, 0x924
    "\xB8\x00\x04\x00\x00"       //mov eax, 0x400
    "\x89\x01"                   //mov [ecx], eax
    "\x89\x41\x04"               //mov [ecx+4], eax
    "\xB8\x01\x00\x00\x00"  //mov eax, 0x1
    "\xC3",                 //ret
    28);
  memcpy(&info.data[sectionOffset + 2], &IoctlBuffer, 4);
}

void txt2_AddMagicSkewValuePatch(SectionInfo& info)
{
  //Just bypass all the various checks and secdrv ioctls by applying the magic number to the decryption skew.
  //This value is found in secdrv.sys GetDebugRegister (Command=3C) at 0x10F60, register dr7 = 0x400.
  //When the ioctl buffer is inspected back in program space, it's not really manipulated in the weird looking
  //decryption function at 0x416B40 (DecryptIoctlMessage). The result from DecryptIoctlMessage is 0x400 - 
  //then that's added to DecryptionValueWithSkew.
  std::vector<uint32_t> offsets = Analyzer::FindSectionPattern(info, "\x33\xC2\x2B\xC2\x83\xE0\x0F", "xxxxxxx");
  if (offsets.size() != 1)
  {
    printf("Expected to find one result for AddMagicSkewValue\n");
    return;
  }
  printf("Found AddMagicSkewValue at 0x%X\n", offsets.at(0));
  size_t sectionOffset = offsets.at(0) - info.VirtualAddress;
  
  size_t start = sectionOffset + 0x13;
  int DecryptionValueWithSkew;
  memcpy(&DecryptionValueWithSkew, &info.data[sectionOffset - 0xD], 4);
  memcpy(&info.data[start],
    "\x8B\x0D\x00\x00\x00\x00"   //mov ecx, [DecryptionValueWithSkew]
    "\x81\xC1\x00\x04\x00\x00"   //add ecx, 0x400 - this sets ZF to 0, so we can then use the jnz
    "\x89\x0D\x00\x00\x00\x00"  //mov [DecryptionValueWithSkew], ecx
    "\xEB\xE6",                 //jmp 0xffffffe8 -0x18
    20);
  memcpy(&info.data[start + 2], &DecryptionValueWithSkew, 4);
  memcpy(&info.data[start + 14], &DecryptionValueWithSkew, 4);
}


void text_SecdrvStatusMessagePatch(SectionInfo& info)
{
  //First calls CanOpenSecdrv then OpenSecdrv using the handle \\\\.\\Secdrv
  //This really doesn't do much besides take in some message then return a bool.
  //The message passed to the ioctl is 0x42EC30
  //size_t sectionOffset = 0x414760 - TEXT_SECTION;
  std::vector<uint32_t> offsets = Analyzer::FindSectionPattern(info, "\x55\x8B\xEC\x8B\x45\x08\x83\x38\x01", "xxxxxxxxx");
  if (offsets.size() != 1)
  {
    printf("Expected to find one result for SecdrvStatusMessage\n");
    return;
  }
  printf("Found SecdrvStatusMessage at 0x%X\n", offsets.at(0));
  size_t sectionOffset = offsets.at(0) - info.VirtualAddress;
  memcpy(&info.data[sectionOffset],
    "\xB8\x01\x00\x00\x00"  //mov eax, 0x1
    "\xC3",                 //ret
    6);
}

void text_TickCountLowPatch(SectionInfo& info)
{
  //First calls CanOpenSecdrv then OpenSecdrv using the handle \\\\.\\Secdrv
  //This really doesn't do much besides take in some message then return a bool.
  //The message passed to the ioctl is 0x42EC30
  

  //This one is kind of clever, they use address 0x7FFE0000 which is always
  //KUSER_SHARED_DATA even on 64-bit Windows. They retrieve TickCountLow in 
  //function 0x4148F8. If the elapsed ticks is > 0xA, return 0.

  //You can essentially bypass this by not debugging that function, this patch
  //is provided to allow others to debug
  
  //size_t sectionOffset = 0x4149DB - TEXT_SECTION;
  std::vector<uint32_t> offsets = Analyzer::FindSectionPattern(info, "\x76\x05\x66\x33\xC0", "xxxxx");
  if (offsets.size() != 1)
  {
    printf("Expected to find one result for TickCountLow\n");
    return;
  }
  printf("Found TickCountLow at 0x%X\n", offsets.at(0));
  size_t sectionOffset = offsets.at(0) - info.VirtualAddress;
  memcpy(&info.data[sectionOffset],
    "\xEB", //jbe -> jmp
    1);
}

/*
ProcessEnvironmentBlock
Thread 5B0 TEB
KUSER_SHARED_DATA = 7FFE0000
GetRandomGeneration returns this value in shared data
shared data inside of the TEB
KUSER_SHARED_DATA
*/


void txt2_BeingDebuggedPEBPatch(SectionInfo& info)
{
  //Uses TIB fs:18 + 0x30 = PEB + 2 = BeingDebugged
  //TODO: There's actually another check for +0x20 in the larger executable
  //size_t sectionOffset = 0x42436A - TXT2_SECTION;

  std::vector<uint32_t> offsets = Analyzer::FindSectionPattern(info, "\x64\xA1\x18\x00\x00\x00\x8B\x48\x30", "xxxxxxxxx");
  if (offsets.size() != 1)
  {
    printf("Expected to find one result for BeingDebuggedPEB\n");
    return;
  }
  printf("Found BeingDebuggedPEB at 0x%X\n", offsets.at(0));
  size_t sectionOffset = offsets.at(0) - info.VirtualAddress;
  memcpy(&info.data[sectionOffset],
    "\x33\xC0"                 //xor eax, eax
    "\x90\x90\x90\x90\x90"     //nop (5)
    "\x90\x90\x90\x90\x90"     //nop (5)
    "\x90",                    //nop
    13);
}

void txt2_CheckKernel32BreakpointPatch(SectionInfo& info)
{
  //Simply jmp 4245A6->42468F. Goes over all functions in the Kernel32 export directory
  //to see if the first byte of any function has a 0xCC
}

void txt2_IsBeingDebuggedPatch(SectionInfo& info)
{
  //4242A9 they decrypt "IsDebuggerPresent" and call from Kernel32.dll
  //size_t sectionOffset = 0x4242D4 - TXT2_SECTION;
  std::vector<uint32_t> offsets = Analyzer::FindSectionPattern(info, "\xFF\x55\xF0\x66\x89\x85\x4C\xFF\xFF\xFF", "xxxxxxxxxx");
  if (offsets.size() != 1)
  {
    printf("Expected to find one result for IsBeingDebugged\n");
    return;
  }
  printf("Found IsBeingDebugged at 0x%X\n", offsets.at(0));
  size_t sectionOffset = offsets.at(0) - info.VirtualAddress;
  memcpy(&info.data[sectionOffset],
    "\x33\xC0"                 //xor eax, eax
    "\x90",                    //nop
    3);
}

void txt2_NTQueryProcessInformationPatch(SectionInfo& info)
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

  std::vector<uint32_t> offsets = Analyzer::FindSectionPattern(info, "\x83\xBD\x2C\xFF\xFF\xFF\x00", "xxxxxxx");
  if (offsets.size() != 1)
  {
    printf("Expected to find one result for NTQueryProcessInformation\n");
    return;
  }
  printf("Found NTQueryProcessInformation at 0x%X\n", offsets.at(0));
  size_t sectionOffset = offsets.at(0) - info.VirtualAddress;
  memcpy(&info.data[sectionOffset],
    "\xEB\x3D"                 //jmp 0x423C96
    "\x90\x90\x90\x90\x90",     //nop (5), correction for debugging
    7);
}

void txt2_SoftICEDebuggerCheck(SectionInfo& info)
{
  // 0x42AB10 = Encrypted \\\\.\\SICE (driver)
  // 0x42AB30 = Encrypted \\\\.\\NTICE (driver)
  
  //Checks to see if SoftICE debugger is running. Not really necessary 
  //to patch, but did so anyways. Takes the file handle result and stores 
  //it onto a stack variable, then copied back into the function argument.
  //You want this to be -1, ie CreateFile(\\\\.\\NTICE) fails.

  //size_t sectionOffset = 0x423DDF - TXT2_SECTION;

  std::vector<uint32_t> offsets = Analyzer::FindSectionPattern(info, "\x8B\x8D\x60\xFF\xFF\xFF\x51\xFF", "xxxxxxxx");
  if (offsets.size() != 1)
  {
    printf("Expected to find one result for SoftICEDebugger\n");
    return;
  }
  printf("Found SoftICEDebugger at 0x%X\n", offsets.at(0));
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


void text_ApplyFauxCDCheckPatch(SectionInfo& info)
{
  //The return result doesn't appear to be used, and nothing
  //interesting happens within the function itself besides
  //checking. This could be a purposeful trap.
  //size_t sectionOffset = 0x40F720 - TEXT_SECTION;

  std::vector<uint32_t> offsets = Analyzer::FindSectionPattern(info, "\x81\xEC\x04\x01\x00\x00\x8D\x44\x24\x00", "xxxxxxxxxx");
  if (offsets.size() != 1)
  {
    printf("Expected to find one result for FauxCDCheck\n");
    return;
  }
  printf("Found FauxCDCheck at 0x%X\n", offsets.at(0));
  size_t sectionOffset = offsets.at(0) - info.VirtualAddress;
  memcpy(&info.data[sectionOffset],
    "\x66\xB8\x01\x00" //mov ax, 1
    "\xC3",            //ret
    5);
}

void txt2_ApplyInterruptDebugPatch(SectionInfo& info)
{
  //0x424F90 function (HardwareDebugTrap) attempts to call "int 0x1"
  //which should result in an exception of 0xC0000005. If a debugger is present,
  //then this is exception is instead passed to the debugger and it won't enter
  //the exception handler.
  //TODO: This does not appear in the larger executable...
  //size_t sectionOffset = 0x424D69 - TXT2_SECTION;

  std::vector<uint32_t> offsets = Analyzer::FindSectionPattern(info, "\xC7\x05\x00\x00\x00\x00\xFF\x00\x00\x00\xE8", "xx????xxxxx");
  if (offsets.size() != 1)
  {
    printf("Expected to find one result for InterruptDebug\n");
    return;
  }
  printf("Found InterruptDebug at 0x%X\n", offsets.at(0));
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

/*
void text_DisableDecryption(SectionInfo& info)
{
  //We are using the already decrypted .text section which
  //is dumped on CD failure
  for (size_t i = 0x40E268; i < 0x40E288; ++i)
  {
    size_t sectionOffset = i - TEXT_SECTION;
    info.data[sectionOffset] = 0x90;
  }
}
*/

struct RelocationData {
  uint32_t size;
  uint32_t offset;
  uint32_t end_offset;
  uint32_t entry;
};

bool FindRelocationTable(SectionInfo& info_reloc, uint32_t VirtualAddress, uint32_t VirtualSize, std::vector<RelocationData>* out = nullptr)
{
  //Search for Base Relocation Block, then add 0x8 for the entries
  //TODO: actually walk the tables correctly
  char buffer[8];
  memset(buffer, 0, sizeof(buffer));
  memcpy(&buffer[0], &VirtualAddress, 4);
  buffer[4] = 0x60; //size
  std::vector<uint32_t> offsets = Analyzer::FindSectionPattern(info_reloc, buffer, "xxxxxxxx", false);
  if (offsets.size() != 1)
  {
    printf("Failed to find relocation table for RVA: 0x%X\n", VirtualAddress);
    return false;
  }
  uint32_t vsize = VirtualSize;
  unsigned int table_offset = offsets.at(0);
  uint32_t entry_va = 0;
  uint32_t entry_size = 0;
  unsigned int va_override = 0x44000;
  uint32_t total_offset = 0;
  while (vsize > 0)
  {
    memcpy(&entry_va, &info_reloc.data[table_offset], 4);
    memcpy(&entry_size, &info_reloc.data[table_offset + 4], 4);
    uint32_t data_size = vsize;
    if (data_size > 0x1000)
      data_size = 0x1000;
    memcpy(&info_reloc.data[table_offset], &va_override, 4);
    printf("Found relocation for 0x%X at 0x%X (0x%X)\n", entry_va, table_offset, table_offset + info_reloc.header.PointerToRawData);
    if (out != nullptr)
    {
      RelocationData data;
      data.size = entry_size - 8;
      data.offset = table_offset;
      data.end_offset = table_offset + entry_size;
      data.entry = entry_va;
      out->push_back(data);
    }
    vsize -= data_size;
    va_override += data_size;
    table_offset += entry_size;
    total_offset += entry_size;
  }
  return true;
}


void ApplyF18Patches(PELoader& loader, bool magic)
{
  const std::string text(".text");
  const std::string txt2(".txt2");
  const std::string data(".data");
  const std::string reloc(".reloc");
  for (SectionInfo& section : loader.GetSections())
  {
    if (text.compare(section.name) == 0)
    {
      text_ApplyFauxCDCheckPatch(section);
      if (!magic)
      {
        text_CanOpenSecdrvPatch(section);
        text_SecdrvProcessIoctlPatch(section);
        text_TickCountLowPatch(section);
        text_SecdrvStatusMessagePatch(section);
      }
      
    }
    else if (txt2.compare(section.name) == 0)
    {

      if (magic)
      {
        txt2_AddMagicSkewValuePatch(section);
      }

      if (!magic)
      {
        txt2_IsBeingDebuggedPatch(section);
        txt2_BeingDebuggedPEBPatch(section);
        txt2_CheckKernel32BreakpointPatch(section);
      }


      txt2_ApplyInterruptDebugPatch(section);
      txt2_drvmgtPatch(section);
      txt2_SoftICEDebuggerCheck(section);
      txt2_NTQueryProcessInformationPatch(section);


    }
    else if (data.compare(section.name) == 0)
    {
      data_StringPatch(section);
    }
    else if (reloc.compare(section.name) == 0)
    {
      FindRelocationTable(section, 0xC000, 0x12A00);
    }
  }
}

void Decrypt(SectionInfo& info_txt, SectionInfo& info_txt2, SectionInfo& info_text,
  SectionInfo& info_reloc, int showOffset, int showSize)
{
  std::vector<RelocationData> reloc_data;
  uint32_t reloc_table = FindRelocationTable(info_reloc, info_text.header.VirtualAddress, info_text.header.Misc.VirtualSize, &reloc_data);
  if (reloc_table == 0) return;
  printf("Found relocation table at: 0x%X\n", reloc_table);


  //txt section is the encrypted data that needs to be decrypted.
  //First pass prepares the encrypted txt section, xor with a rolling key - 8 bytes
  //The second pass xors with the txt2 section, and uses the secdrv kernel key every 16 bytes
  //Third pass will update the skew value as a result from the text section
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
  unsigned int NextSkew = 0;
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
    if ((i + 1) % 0x10 == 0) //421DB9
      decryption_skew += 0x400; //dr7 result from secdrv driver
    if ((i + 1) % 0x1000 == 0)
    {
      
      //TODO: figure out size and info_text.data starting offset  ie text_index
      //text_index is done via sectionDifference in CreateNextDecryptionSkewFromText:
      NextSkew = 0;
      int size_data = info_text.header.SizeOfRawData;
      unsigned int text_index = 0;
      int reloc_index = 0;
      reloc_table = reloc_data.at(reloc_index).offset + 8;
      unsigned int table_index = reloc_table;
      unsigned short last_index = 0;
      while (size_data > 0)
      {
        unsigned short index_entry;
        memcpy(&index_entry, &info_reloc.data[table_index], 2);
        unsigned short index_offset = index_entry & 0xFFF;
        unsigned short index_end = index_entry >> 0xC;
        if(index_end)
        switch (index_end)
        {
        case 1:
        case 2:
          index_end = last_index + 2;
          break;
        case 3:
        case 4:
        case 5:
          index_end = last_index + 4;
          break;
        default:
          index_end = last_index + 0;
        }
        unsigned int size_count = index_offset;
        size_count =  size_count - index_end;
        if (size_count <= 0)
          size_count = index_offset;
        printf("[0x%X] index: 0x%X, size offset: 0x%X, index_end:0x%X\n", table_index, index_offset, size_count, index_end);
        last_index = index_offset;
        table_index = table_index + 2;
        if (table_index == reloc_data.at(reloc_index).end_offset)
        {
          reloc_table = reloc_data.at(++reloc_index).offset + 8;
          printf("Switching to new table (%d): 0x%X\n", reloc_index, reloc_data.at(reloc_index).entry);
          table_index = reloc_table;
          last_index = 0;
        }
       // unsigned int size_count = size_data;
       // if (size_count > 0x1000)
       //   size_count = 0x1000;
        unsigned int starting_val = 0xFD379AB1;
        unsigned int text_index = index_end == size_count ? 0 : index_end;
        for (unsigned int j = size_count; j > 0; j--)
        {
          unsigned int v1 = info_text.data[text_index++] & 0xFF;
          v1 = v1 * starting_val;
          NextSkew += v1;
          unsigned int v2 = starting_val * 0xA7753394;
          starting_val = v2 + (j - 1) + 0x3BC62BB2;
        }
        size_data -= size_count;
        printf("Next Skew: 0x%X\n", NextSkew);
        if (NextSkew == 0x2D813BF9)
        {
          printf("foiund....\n");
          getchar();
        }
      }
      printf("Final decryption skew: 0x%X\n", NextSkew);
      decryption_skew += NextSkew;
    }
  }
 
  unsigned long vaddr = WIN32_PE_ENTRY + info_txt.header.VirtualAddress;
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

