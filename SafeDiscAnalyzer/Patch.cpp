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

void txt_GetDriveTypeA(PELoader& loader, bool patch)
{
  //Simple patch to bypass GetDriveTypeA = DRIVE_CDROM (5)
  //size_t sectionOffset = 0x40565A - TXT_SECTION;
  SectionInfo& info = loader.GetSectionMap().at(SectionType::TXT);
  std::vector<uint32_t> offsets = Analyzer::FindSectionPattern(info,
    "\xFF\x15\x00\x00\x00\x00\x83\xF8\x05\x0F\x85", "xx????xxxxx", loader.GetImageBase());
  if (offsets.size() != 2)
  {
    printf("Expected to find two results for GetDriveTypeA\n");
    return;
  }

  //Use the first result, this should be the first call inside of SafeDiscMain
  //inc edi is used later on when passed to IntenseChecking(InfoStruct, char* appName, int passedCDChecks)
  printf("[.txt] Found GetDriveTypeA at 0x%X, patching: %s\n", offsets.at(0), sbool(patch));
  if (!patch) return;
  size_t sectionOffset = offsets.at(0) - info.VirtualAddress;
  sectionOffset += 9; //set pointer on the jnz
  memcpy(&info.data[sectionOffset],
    "\x47\x90\x90\x90\x90\x90",          //inc edi, nop(5)
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

void txt_UNK_CDROMCheck2(PELoader& loader, bool patch)
{
  //This is part of IntenseChecking
  SectionInfo& info = loader.GetSectionMap().at(SectionType::TXT);
  std::vector<uint32_t> offsets = Analyzer::FindSectionPattern(info,
    "\x83\xC4\x04\x85\xC0\x74\x07\x33\xC0", "xxxxxxxxx", loader.GetImageBase());
  if (offsets.size() != 1)
  {
    printf("Expected to find one result for UNK_CDROMCheck2\n");
    return;
  }

  printf("[.txt] Found UNK_CDROMCheck2 at 0x%X, patching: %s\n", offsets.at(0), sbool(patch));
  if (!patch) return;
  size_t sectionOffset = offsets.at(0) - info.VirtualAddress;
  sectionOffset += 5; //set pointer on the call RealCDRomCheckTracks (E8)
  memcpy(&info.data[sectionOffset],
    "\xEB",          //jnz -> jmp
    1);
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
  txt_GetDriveTypeA(loader, true);
  txt_UNK_CDROMCheck1(loader, true);
  txt_UNK_CDROMCheck2(loader, true);
  return true;
}