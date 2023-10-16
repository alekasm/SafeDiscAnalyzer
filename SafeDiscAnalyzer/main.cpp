#include "PELoader.h"
#include "Analyzer.h"
#include "F18Patch.h"
#include <vector>
#include <unordered_map>


int main(int argc, const char** argv)
{

  if (argc < 2)
  {
    printf("Usage: ./SafeDiscAnalyzer.exe <file> <args>\nArguments:\n");
    printf("-antiasm\tpatches anti-disassembler routines\n");
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

  std::string hash;
  if (Analyzer::CreateMD5Hash(argv[1], hash))
    printf("Md5: %s\n", hash.c_str());


  PELoader loader;
  loader.LoadPEFile(argv[1]);
  for (const SectionInfo& section : loader.GetSections())
  {
    if (!section.initialized)
    {
      printf("Unable to find section: %s\n", section.name);
      return 0;
    }
  } 

  if (decrypt)
  {
    Decrypt(loader.GetSections().at(2), loader.GetSections().at(1),
      loader.GetSections().at(0), dOffset, dSize);
    return 0;
  }

  if (antiasm)
  {
    printf("Analyzing sections for anti-disassembler techniques\n");
    for (SectionInfo& section : loader.GetSections())
      Analyzer::PatchSafeDiscAntiDisassembler(section);
  }

  if (bypass)
  {
    printf("Applying F18 patches\n");
    ApplyF18Patches(loader, magic);
  }

  bool result = loader.PatchPEFile(argv[1]);

  printf("Patch successful = %s\n", result ? "true" : "false");
  for (SectionInfo& section : loader.GetSections())
    delete section.data;
  return 0;
}