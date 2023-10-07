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
    return 0;
  }



  bool antiasm = false;
  bool bypass = false;
  bool magic = false;
  for (int i = 2; i < argc; ++i)
  {
    if (std::string("-antiasm").compare(argv[i]) == 0)
      antiasm = true;
    else if (std::string("-bypass").compare(argv[i]) == 0)
      bypass = true;
    else if (std::string("-magic").compare(argv[i]) == 0)
      magic = true;
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

  //Decrypt(loader.GetSections().at(2), loader.GetSections().at(1), 128 - 1);
  //return 0;

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