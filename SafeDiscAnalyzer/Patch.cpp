#include "Patch.h"
#include "Util.h"

//#define DEBUGGING_ENABLED
//#define DEBUG_INTERMEDIATE_RELOCATION_SKEW
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


void txt_SafeDiscMainStartingChecks(PELoader& loader, bool patch)
{
  //Patches over GetDriveTypeA, GetCDROMTrackCount,
  //VerifyVolumeDescription, ValidateCDillaStruct
  SectionInfo& info = loader.GetSectionMap().at(SectionType::TXT);
  std::vector<uint32_t> offsets = Analyzer::FindSectionPattern(info,
    "\xFF\x15\x00\x00\x00\x00\x83\xF8\x05\x0F\x85", "xx????xxxxx", loader.GetImageBase());
  if (offsets.size() != 2)
  {
    printf("Expected to find two results for SafeDiscMainStartingChecks\n");
    return;
  }

  //Use the second result
  printf("[.txt] Found SafeDiscMainStartingChecks at 0x%X, patching: %s\n", offsets.at(1), sbool(patch));
  if (!patch) return;
  size_t sectionOffset = offsets.at(1) - info.VirtualAddress;
  sectionOffset += 9; //set pointer on the jnz
  memcpy(&info.data[sectionOffset],
    "\xEB\x6A"                    //jmp 6A (skips 3 check blocks)
    "\x90\x90\x90\x90",          //nop(6)
    6);

  //sub_40F780 drive check needs to return 1 for true
}

void txt_GetCDROMTrackCount(PELoader& loader, bool patch)
{
  SectionInfo& info = loader.GetSectionMap().at(SectionType::TXT);
  std::vector<uint32_t> offsets = Analyzer::FindSectionPattern(info,
    "\xC7\x00\x01\x00\x00\x00\xE8", "xxxxxxx", loader.GetImageBase());
  if (offsets.size() != 1)
  {
    printf("Expected to find one result for GetCDROMTrackCount\n");
    return;
  }

  printf("[.txt] Found GetCDROMTrackCount at 0x%X, patching: %s\n", offsets.at(0), sbool(patch));
  if (!patch) return;
  size_t sectionOffset = offsets.at(0) - info.VirtualAddress;
  sectionOffset += 6; //set pointer on the call RealCDRomCheckTracks (E8)
  memcpy(&info.data[sectionOffset],
    "\x90\x90\x90\x90\x90"          //nop (5) - call RealCDRomCheckTracks
    "\x90\x90\x90",                 //nop (3) - add esp, 0xC
    8);
}

void txt_UNK_CDROMCheck1(PELoader& loader, bool patch)
{
  //This is part of IntenseChecking
  SectionInfo& info = loader.GetSectionMap().at(SectionType::TXT);
  std::vector<uint32_t> offsets = Analyzer::FindSectionPattern(info,
    "\x83\xC4\x08\x85\xC0\x74\x07\x33\xC0", "xxxxxxxxx", loader.GetImageBase());
  if (offsets.size() != 1)
  {
    printf("Expected to find one result for UNK_CDROMCheck1\n");
    return;
  }

  printf("[.txt] Found UNK_CDROMCheck1 at 0x%X, patching: %s\n", offsets.at(0), sbool(patch));
  if (!patch) return;
  size_t sectionOffset = offsets.at(0) - info.VirtualAddress;
  sectionOffset += 5; //set pointer on the call RealCDRomCheckTracks (E8)
  memcpy(&info.data[sectionOffset],
    "\xEB",          //jnz -> jmp
    1);
}


void txt2_AddPETableSectionLookup(PELoader& loader, bool patch)
{
  //This takes an unused SectionType in ReadPETableForSection, and modifies it so we can select
  //sections easily. The current section types used are:
  //1 = Executable Section (20000020h)
  //2 = Data Section
  //3 = Not Used (.bss)
  //4 = Not Used (default case, do nothing)  <- reusing this case
  //5 = Resource Table
  //6 = Import Table
  //7 = Export Table
  //8 = Relocation Table
  //9 = TLS Table
  //A = Relocation Data
  //B = Import Address Table

  SectionInfo& info = loader.GetSectionMap().at(SectionType::TXT2);
  //This is case 4 (default case, unused)
  std::vector<uint32_t> offsets = Analyzer::FindSectionPattern(info,
    "\xC7\x02\x00\x00\x00\x00\xC7\x45\x00\x00\x00\x00\x00\xC7\x06\x00\x00\x00\x00", "xxxxxxxxxxxxxxxxxxx", loader.GetImageBase());
  if (offsets.size() != 1)
  {
    printf("Expected to find one result for AddPETableSectionLookup\n");
    return;
  }
  printf("[.txt2] Found AddPETableSectionLookup at 0x%X, patching: %s\n", offsets.at(0), sbool(patch));
  if (!patch) return;
  size_t sectionOffset = offsets.at(0) - info.VirtualAddress;

  memcpy(&info.data[sectionOffset],
    "\x8D\x54\x24\x10"              //lea edx, dword ptr ss:[esp+0x10]
    "\x52"                          //push edx
    "\x53"                          //push ebx
    "\x50"                          //push eax
    "\x33\xC9"                      //xor ecx, ecx
    "\x41"                          //inc ecx
    "\x90\x90\x90\x90"              //nop (4)
    //"\x41"                        //inc ecx
    //"\xC1\xE1\x1C"                //shl ecx, 0x1C
    "\x51"                          //push ecx - push 0x20000000
    "\x51"                          //push ecx - above is a 1-byte optimization
    "\xE9\xD3\xFE\xFF\xFF",         //jmp - 12D
    21);
}

void txt_HashExecutableSectionsType(PELoader& loader, bool patch)
{
  //Uses the AddPETableSectionLookup patch to leverage Type 4
  SectionInfo& info = loader.GetSectionMap().at(SectionType::TXT);
  std::vector<uint32_t> offsets = Analyzer::FindSectionPattern(info,
    "\x6A\x01\x8B\x4D\x08\x51\xE8", "xxxxxxx", loader.GetImageBase());
  if (offsets.size() != 1)
  {
    printf("Expected to find one result for HashExecutableSectionsType\n");
    return;
  }

  printf("[.txt] Found HashExecutableSectionsType at 0x%X, patching: %s\n", offsets.at(0), sbool(patch));
  if (!patch) return;
  size_t sectionOffset = offsets.at(0) - info.VirtualAddress;
  info.data[sectionOffset + 1] = 0x04;
}

void CopyDecryptedSections(PELoader& loader)
{
  //This will not work with the dll because there needs to be fixups
  //for the relocations
  SectionInfo& info_txt = loader.GetSectionMap().at(SectionType::TXT);
  SectionInfo& info_txx = loader.GetSectionMap().at(SectionType::TXX);
  unsigned int size = info_txt.header.SizeOfRawData;
  memcpy(info_txx.data, info_txt.data, size);
}

void txt_CDRomRead1(PELoader& loader, bool patch)
{
  //IntenseCheckingInner_1
  //This pulls off 0x930 bytes off cdbLogicalBlock 0x10 from the disc
  //We will need separate patches to fix the expected data
  SectionInfo& info = loader.GetSectionMap().at(SectionType::TXT);

  std::vector<uint32_t> offsets = Analyzer::FindSectionPattern(info,
    "\x0F\xBF\x45\x08", "xxxx", loader.GetImageBase()); //movsx eax, word ptr [ebp + 8]
  if (offsets.size() != 1)
  {
    printf("Expected to find one result for CDRomRead1\n");
    return;
  }

  printf("[.txt] Found CDRomRead1 at 0x%X, patching: %s\n", offsets.at(0), sbool(patch));
  if (!patch) return;
  size_t sectionOffset = offsets.at(0) - info.VirtualAddress;
  memcpy(&info.data[sectionOffset],
    "\xEB\x56\x90\x90",          //jmp 0x58 (next block)
    4);
}

void txt_CDRomCDillaCheck(PELoader& loader, bool patch)
{
  //IntenseCheckingInner_1
  //[block 0x10] + 0xFB3 (size = 0x40) gets decrypted to C-Dilla
  //This bypasses the read, and then the check

  SectionInfo& info = loader.GetSectionMap().at(SectionType::TXT);

  //lea edi, [ebp - 0x54]
  //mov esi, ?? ?? ?? ??
  std::vector<uint32_t> offsets = Analyzer::FindSectionPattern(info,
    "\x8D\x7D\xAC\xBE", "xxxx", loader.GetImageBase());
  if (offsets.size() != 1)
  {
    printf("Expected to find one result for CDRomCDillaCheck\n");
    return;
  }

  printf("[.txt] Found CDRomCDillaCheck at 0x%X, patching: %s\n", offsets.at(0), sbool(patch));
  if (!patch) return;
  size_t sectionOffset = offsets.at(0) - info.VirtualAddress;
  memcpy(&info.data[sectionOffset],
    "\xEB\x2A\x90",          //jmp 0x2A (next block - check passed)
    3);
}

void txt_RandomizeIterations(PELoader& loader, bool patch)
{
  //IntenseCheckingInner_1 - might not be really necessary, but will
  //help with debugging
  SectionInfo& info = loader.GetSectionMap().at(SectionType::TXT);

  //add eax, 0xA;  (uses RandomizeValue + 0xA)
  std::vector<uint32_t> offsets = Analyzer::FindSectionPattern(info,
    "\x83\xC0\x0A", "xxx", loader.GetImageBase());
  if (offsets.size() != 1)
  {
    printf("Expected to find one result for ValidateTime\n");
    return;
  }

  printf("[.txt] Found ValidateTime at 0x%X, patching: %s\n", offsets.at(0), sbool(patch));
  if (!patch) return;
  size_t sectionOffset = offsets.at(0) - info.VirtualAddress;
  memcpy(&info.data[sectionOffset],
    "\x31\xC0"          //xor eax, eax
    "\x40",             //inc eax
    3);
}

void txt_ValidateCDROM(PELoader& loader, bool patch)
{
  SectionInfo& info = loader.GetSectionMap().at(SectionType::TXT);
  //call ?? ?? ?? ??
  //mov esi, dword ptr [ebp + 0xc]
  std::vector<uint32_t> offsets = Analyzer::FindSectionPattern(info,
    "\xE8\x00\x00\x00\x00\x8B\x75\x0C", "x????xxx", loader.GetImageBase());
  if (offsets.size() != 1)
  {
    printf("Expected to find one result for ValidateCDROM\n");
    return;
  }

  printf("[.txt] Found ValidateCDROM at 0x%X, patching: %s\n", offsets.at(0), sbool(patch));
  if (!patch) return;
  size_t sectionOffset = offsets.at(0) - info.VirtualAddress;
  sectionOffset -= 0x6; //start of function, just xor it out
  memcpy(&info.data[sectionOffset],
    "\x31\xC0"          //xor eax, eax
    "\xC3",             //retn
    3);
}

void txt_FixCDillaChecks(PELoader& loader, bool patch)
{
  //C-Dilla check should return 1
  //C-Dilla check 40405D, 403BBA, 4043CF

  //4045AB
  //?? 55 10 BE
  //mov ??, dword ptr [ebp + 0x10]
  //mov esi, ?? ?? ?? ??

  SectionInfo& info = loader.GetSectionMap().at(SectionType::TXT);
  std::vector<uint32_t> offsets = Analyzer::FindSectionPattern(info,
    "\x00\x55\x10\xBE", "?xxx", loader.GetImageBase());
  if (offsets.size() != 1)
  {
    printf("Expected to find one result for FixCDillaChecks\n");
    return;
  }
  printf("[.txt] Found FixCDillaChecks at 0x%X, patching: %s\n", offsets.at(0), sbool(patch));
  if (!patch) return;
  size_t sectionOffset = offsets.at(0) - info.VirtualAddress;

  memcpy(&info.data[sectionOffset],
    "\xB8\x01\x00\x00\x00" //mov eax, 1
    "\x5F"                 //pop edi
    "\x5E"                 //pop esi
    "\x5B"                 //pop ebx
    "\x89\xEC"             //mov esp, ebp
    "\x5D"                //pop ebp
    "\xC3",                //retn
    12);

  /*
  SectionInfo& info = loader.GetSectionMap().at(SectionType::TXT);
  std::vector<uint32_t> offsets = Analyzer::FindSectionPattern(info,
    "\x00\x4E\x16\x00\x00\x00\xE8\x00\x00\x00\x00\x83\xC4\x0C\x66\x3D\x01\x00",
    "?xx???x????xxxxxxx", loader.GetImageBase());
  if (offsets.size() != 1)
  {
    printf("Expected to find one result for ValidateCDillaDecryption\n");
    return;
  }
  printf("[.txt] Found ValidateCDillaDecryption at 0x%X, patching: %s\n", offsets.at(0), sbool(patch));
  if (!patch) return;
  size_t sectionOffset = offsets.at(0) - info.VirtualAddress;
  
  memcpy(&info.data[sectionOffset],
    "\x31\xC0"          //xor eax, eax
    "\xC3",             //retn
    3);
  */

}

void txt_RetrieveInfoFromCDROM(PELoader& loader, bool patch)
{
  //4045AB
  //A1 ?? ?? ?? ?? 55 8B 6C  24 08
  //mov eax, bPreviousVerificationBlock10h
  //push ebp
  //mov ebp, [esp + 0x8]
  SectionInfo& info = loader.GetSectionMap().at(SectionType::TXT);
  std::vector<uint32_t> offsets = Analyzer::FindSectionPattern(info,
    "\xA1\x00\x00\x00\x00\x55\x8B\x6C\x24\x08", "x????xxxxx", loader.GetImageBase());
  if (offsets.size() != 1)
  {
    printf("Expected to find one result for RetrieveInfoFromCDROM\n");
    return;
  }
  printf("[.txt] Found RetrieveInfoFromCDROM at 0x%X, patching: %s\n", offsets.at(0), sbool(patch));
  if (!patch) return;
  size_t sectionOffset = offsets.at(0) - info.VirtualAddress;

  memcpy(&info.data[sectionOffset],
    "\x31\xC0"  //xor eax, eax
    "\xC3",     //retn
    3);
}

void txt_RetrieveVolumeInfoFromCDROM(PELoader& loader, bool patch)
{
  //This is the basis for many of the CDRom calls to grab data off the disc.
  //There is one check that must fail this read, which will be a separate patch.
  //mov bl, byte ptr [esp+4+driveLetter]
  SectionInfo& info = loader.GetSectionMap().at(SectionType::TXT);
  std::vector<uint32_t> offsets = Analyzer::FindSectionPattern(info,
    "\x8A\x5C\x24\x08 ", "xxxx", loader.GetImageBase());
  if (offsets.size() != 1)
  {
    printf("Expected to find one result for RetrieveVolumeInfoFromCDROM\n");
    return;
  }
  printf("[.txt] Found RetrieveVolumeInfoFromCDROM at 0x%X, patching: %s\n", offsets.at(0), sbool(patch));
  if (!patch) return;
  size_t sectionOffset = offsets.at(0) - info.VirtualAddress;
  //This is the only path taken on WindowsNT machines
  memcpy(&info.data[sectionOffset],
    "\x31\xC0"  //xor eax, eax
    "\x5B"      //pop ebx
    "\xC3",     //retn
    4);
}



void text_DecryptCDillaStruct(PELoader& loader, bool patch)
{
  //This check is used in numerous places to validate the CD-ROM is inserted
  //The data is provided by cdbLogicalBlock 0x10 at offset 4B3, which is then
  //decrypted and validated

  //push ebp
  //mov ebp, esp
  //sub esp, 0x40
  SectionInfo& info = loader.GetSectionMap().at(SectionType::TEXT);
  std::vector<uint32_t> offsets = Analyzer::FindSectionPattern(info,
    "\x55\x8B\xEC\x83\xEC\x40 ", "xxxxxx", loader.GetImageBase());
  if (offsets.size() != 1)
  {
    printf("Expected to find one result for DecryptCDillaStruct\n");
    return;
  }
  printf("[.text] Found DecryptCDillaStruct at 0x%X, patching: %s\n", offsets.at(0), sbool(patch));
  if (!patch) return;

  //This just copies over the expected CDilla struct over to the provided argument
  //CDilla Verification Struct:
  //0x00 - 0x07 = C-Dilla String
  //0x08 - 0x09 = 0x02 (Verification)
  //0x0A - 0x0B = 0x00 (Verification)
  //0x0C - 0x0F = Next Logical Block (0x320)
  //0x10 - 0x13 = Unknown, used with time checks (0x279D)
  //0x14 - 0x15 = Unknown (05 05)
  //0x16 - 0x19 = Unknown (0x22B69FD6)
  //0x1A - 0x1B = Unknown (0)
  //0x1C - 0x1F = Unknown (0x18)

  //003E5BAB  43 2D 44 69 6C 6C 61 00 02 00 00 00 20 03 00 00  C - Dilla..... ...
  //003E5BBB  9D 27 00 00 05 05 D6 9F B6 22 00 00 18 00 00 00  .'....Ö.¶"...... 

  size_t sectionOffset = offsets.at(0) - info.VirtualAddress;
  memcpy(&info.data[sectionOffset],
    "\x8B\x5C\x24\x08"          //mov ebx, dword ptr [esp + 0x8] <- output struct
    "\xE8\x00\x00\x00\x00"      //call 0
    "\x58"                      //pop eax
    "\x83\xE8\x05"              //sub eax, 5 (make relative)
    "\x83\xC0\x19"              //add eax, 0x19 - location of data
    "\x89\xDF"                  //mov edi, ebx
    "\x89\xC6"                  //mov esi, eax
    "\xB9\x08\x00\x00\x00"      //mov ecx, 8
    "\xF3\xA5"                  //rep movsd
    "\xEB\x20"                  //jmp 0x20

    //Data:
    "\x43\x2D\x44\x69\x6C\x6C\x61\x00\x02\x00\x00\x00\x20\x03\x00\x00"
    "\x9D\x27\x00\x00\x05\x05\xD6\x9F\xB6\x22\x00\x00\x18\x00\x00\x00"

    "\x33\xC0"                  //xor eax, eax
    "\x40"                      //inc eax
    "\xC3",                     //retn
    65);
}

bool ApplyPatches(PELoader& loader, bool isDLL)
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

  //New Patches - only possible with decryption
  //Currently decryption/encryption not supported with dlls
  if (!isDLL)
  {
    txt2_AddPETableSectionLookup(loader, true);
    txt_HashExecutableSectionsType(loader, true);


    txt_SafeDiscMainStartingChecks(loader, true);

    txt_UNK_CDROMCheck1(loader, true); //IntenseChecking
    text_DecryptCDillaStruct(loader, true);
    txt_RetrieveVolumeInfoFromCDROM(loader, true);

    
    //Solved with RetrieveVolumeInfoFromCDROM
    txt_CDRomRead1(loader, false);

    //Solved with DecryptCDillaStruct
    txt_CDRomCDillaCheck(loader, false);

    //Solved with RetrieveVolumeInfoFromCDROM + DecryptCDillaStruct
    txt_RetrieveInfoFromCDROM(loader, false);
    
    txt_RandomizeIterations(loader, true);
    txt_ValidateCDROM(loader, false);
    txt_FixCDillaChecks(loader, false);
    
    //VerifyBufferCDilla(0 = returns 1 for true
    //4143A3 check this result
  }
  return true;
}