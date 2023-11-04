#include "PELoader.h"
#include "Analyzer.h"
#include "Patch.h"
#include <vector>
#include <unordered_map>

#include <Ntddscsi.h>
int main(int argc, const char** argv)
{


  if (argc < 2)
  {
    printf("Usage: ./SafeDiscAnalyzer.exe <file> <args>\nArguments:\n");
    printf("-antiasm\tpatches anti-disassembler routines for disassembly\n");
    printf("-bypass\tapplies various patches to crack the game\n");
    printf("-magic\tuses magic value from kernel driver + decryption\n");
    printf("-decrypt <offset> <size>\tshows decryption of txt at offset\n");
    return 0;
  }


  bool antiasm = false;
  bool bypass = false;
  bool magic = false;
  bool decrypt = false;
  int dOffset = 0;
  int dSize = 0;
  for (int i = 2; i < argc; ++i)
  {
    if (std::string("-antiasm").compare(argv[i]) == 0)
      antiasm = true;
    else if (std::string("-bypass").compare(argv[i]) == 0)
      bypass = true;
    else if (std::string("-magic").compare(argv[i]) == 0)
      magic = true;
    else if (std::string("-decrypt").compare(argv[i]) == 0)
    { //eg: -decrypt FF0 80
      if (i + 3 > argc)
      {
        printf("-decrypt requires offset and size args\n");
        return 0;
      }
      dOffset = strtoull(argv[i + 1], NULL, 16);
      dSize = strtoull(argv[i + 2], NULL, 16);
      decrypt = true;
      i += 2;
    }
  }

  if (antiasm && (bypass || decrypt))
  {
    printf("Cannot using -antiasm with -bypass or -decrypt\n");
    return 0;
  }

  std::string hash;
  if (Analyzer::CreateMD5Hash(argv[1], hash))
    printf("Md5: %s\n", hash.c_str());


  PELoader loader;
  if (!loader.LoadPEFile(argv[1]))
    return 0;

  if (!loader.FoundAllSections())
    return 0;


  if (decrypt)
  {
    Decrypt(loader, dOffset, dSize);
    return 0;
  }

  if (antiasm)
  {
    printf("Analyzing sections for anti-disassembler techniques\n");
    SectionInfo& info_txt2 = loader.GetSectionMap().at(SectionType::TXT2);
    SectionInfo& info_text = loader.GetSectionMap().at(SectionType::TEXT);
    Analyzer::PatchSafeDiscAntiDisassembler(info_txt2);
    Analyzer::PatchSafeDiscAntiDisassembler(info_text);
  }

  if (bypass)
  {
    printf("Applying patches\n");
    ApplyPatches(loader, magic);
  }

  bool result = loader.PatchPEFile(argv[1]);

  printf("Patch successful = %s\n", result ? "true" : "false");
  loader.Destroy();
  return 0;
}