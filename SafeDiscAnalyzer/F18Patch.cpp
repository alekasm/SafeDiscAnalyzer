#include "F18Patch.h"
#define TXT2_SECTION 0x41F000
#define TEXT_SECTION 0x40C000

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

  size_t sectionOffset = 0x4229F0 - TXT2_SECTION;
  memcpy(&info.data[sectionOffset],
    "\x8B\x4D\x10"          //mov ecx, dword ptr [ebp + 0x10]
    "\xB8\x64\x00\x00\x00"  //mov eax, 0x64
    "\x89\x01"              //mov dword ptr [ecx], eax
    "\xB8\x01\x00\x00\x00"  //mov eax, 0x1
    "\xC3",                 //ret
    16);


  //sub_40F780 drive check needs to return 1 for true
}


//Contains three separate debugging checks.
//1. 4242A9 they decrypt "IsDebuggerPresent" and call from Kernel32.dll
//2. Uses TIB fs:18 + 0x30 = PEB + 2 = BeingDebugged
//3. Uses DeviceIoControl to communicate with driver  \\\\.\\Secdrv

//These catches will then determine how they manipulate arg_0
//If SecdrvVerification fails, arg_0 & 0x2D325697.
//If SecdrvVerification passes, arg_0 = var_C0

//If BeingDebuggedPEB || IsDebuggerPresent, arg_0 & 0FD356997
//If dwPlatformId != VER_PLATFORM_WIN32_NT, arg_0 & 1145373A
//If A8_Counter > 0, arg_0 & 5185DADE

//The Objective is arg_0 = var_C0, which is complicated inside of SecdrvVerification

void text_CanOpenSecdrvPatch(SectionInfo& info)
{
  //First calls CanOpenSecdrv then OpenSecdrv using the handle \\\\.\\Secdrv
  //This really doesn't do much besides take in some message then return a bool.
  size_t sectionOffset = 0x4147A3 - TEXT_SECTION;

  memcpy(&info.data[sectionOffset],
    "\xB8\x01\x00\x00\x00"  //mov eax, 0x1
    "\xC3",                 //ret
    6);
}

void text_SecdrvProcessIoctlPatch(SectionInfo& info)
{
  //First calls CanOpenSecdrv then OpenSecdrv using the handle \\\\.\\Secdrv
  //This really doesn't do much besides take in some message then return a bool.
  //The message passed to the ioctl is 0x42EC30
  size_t sectionOffset = 0x414818 - TEXT_SECTION;

  memcpy(&info.data[sectionOffset],
    "\xB8\x01\x00\x00\x00"  //mov eax, 0x1
    "\xC3",                 //ret
    6);
}

void text_SecdrvStatusMessagePatch(SectionInfo& info)
{
  //First calls CanOpenSecdrv then OpenSecdrv using the handle \\\\.\\Secdrv
  //This really doesn't do much besides take in some message then return a bool.
  //The message passed to the ioctl is 0x42EC30
  size_t sectionOffset = 0x414760 - TEXT_SECTION;

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
  
  size_t sectionOffset = 0x4149DB - TEXT_SECTION;
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
  size_t sectionOffset = 0x42436A - TXT2_SECTION;
  memcpy(&info.data[sectionOffset],
    "\x33\xC0"                 //xor eax, eax
    "\x90\x90\x90\x90\x90"     //nop (5)
    "\x90\x90\x90\x90\x90"     //nop (5)
    "\x90",                    //nop
    13);
}

void txt2_IsBeingDebuggedPatch(SectionInfo& info)
{
  //4242A9 they decrypt "IsDebuggerPresent" and call from Kernel32.dll
  size_t sectionOffset = 0x4242D4 - TXT2_SECTION;
  memcpy(&info.data[sectionOffset],
    "\x33\xC0"                 //xor eax, eax
    "\x90",                    //nop
    3);
}

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

//42A978 = ReadProcessMemory
//42A9A0 = WriteProcessMemory
//42A9B8 = VirtualProtect

//42AB50 = IsDebuggerPresent

void txt2_ProcessDebugPortPatch(SectionInfo& info)
{
  //Function: 0x4239DF
  //SafeDiscError(0x04, 0x07, 0x10)
  //This function has various strings that are decrypted
  // 0x42AB80 = Encrypted Ntdll
  // 0x42AB90 = Encrypted NtQueryInformationProcess
  // 0x42AB00 = Encrypted Kernel32.dll
  // 0x42AB40 = Encrypted CreateFileA
  // 0x42AB10 = Encrypted \\\\.\\SICE (driver)
  // 0x42AB30 = Encrypted \\\\.\\NTICE (driver)
  // 0x423C1B = CALL NtQueryInformationProcess
  //  - arg0:GetCurrentProcess()
  //  - arg1: 7, ProcessDebugPort
  //  - arg2: stack variable, out ProcessInformation
  //  - arg3: 4, ProcessInformationLength
  //  - arg4: 0, ReturnLength (optional)

  //Patch:
  //xor eax, eax
  //ret

  size_t sectionOffset = 0x422B40 - TXT2_SECTION;
  memcpy(&info.data[sectionOffset], "\x31\xC0\xC3", 3);
}

void text_ApplyPlatformPatch(SectionInfo& info)
{
  //Just checks dwPlatformId, this check is done a bunch already
  //and its not really necessary to patch
  //SafeDiscError3 = jne->jmp = 0x40E082 = 75 -> EB
  //SafeDiscError(0x03, 0x08, 0x10)
  size_t sectionOffset = 0x40E082 - TEXT_SECTION;
  info.data[sectionOffset] = 0xEB;
}

void text_ApplyCDCheckPatch(SectionInfo& info)
{
  //The return result doesn't appear to be used, and nothing
  //interesting happens within the function itself besides
  //checking. This could be a purposeful trap.
  size_t sectionOffset = 0x40F720 - TEXT_SECTION;
  memcpy(&info.data[sectionOffset],
    "\x66\xB8\x01\x00" //mov ax, 1
    "\xC3",            //ret
    5);
}

void txt2_ApplyInterruptDebugPatch(SectionInfo& info)
{
  //int1 (CD 01)  = 0x42519D -> 90 90
  size_t sectionOffset = 0x42519D - TXT2_SECTION;
  info.data[sectionOffset] = 0x90;
  info.data[sectionOffset + 1] = 0x90;
}

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


void ApplyF18Patches(std::vector<SectionInfo>& sections)
{
  const std::string text(".text");
  const std::string txt2(".txt2");
  for (SectionInfo& section : sections)
  {
    if (text.compare(section.name) == 0)
    {
      text_CanOpenSecdrvPatch(section);
      text_SecdrvProcessIoctlPatch(section);
      text_ApplyCDCheckPatch(section);
      text_SecdrvStatusMessagePatch(section);
      text_TickCountLowPatch(section);
      //text_DisableDecryption(section);
    }
    else if (txt2.compare(section.name) == 0)
    {
      txt2_ProcessDebugPortPatch(section);
      txt2_ApplyInterruptDebugPatch(section);
      txt2_drvmgtPatch(section);
      txt2_IsBeingDebuggedPatch(section);
      txt2_BeingDebuggedPEBPatch(section);
    }
  }
}

