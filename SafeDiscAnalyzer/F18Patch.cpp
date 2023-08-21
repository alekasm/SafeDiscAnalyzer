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

void ApplyF18Patches(std::vector<SectionInfo>& sections)
{
  const std::string text(".text");
  const std::string txt2(".txt2");
  for (SectionInfo& section : sections)
  {
    if (text.compare(section.name) == 0)
    {
      text_ApplyCDCheckPatch(section);
    }
    else if (txt2.compare(section.name) == 0)
    {
      txt2_ProcessDebugPortPatch(section);
      txt2_ApplyInterruptDebugPatch(section);
      txt2_drvmgtPatch(section);
    }
  }
}

