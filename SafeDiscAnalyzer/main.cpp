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
    printf("-decrypt <offset> <size>\tshows decryption of txt at offset\n");
    return 0;
  }

  bool antiasm = false;
  bool bypass = false;
  bool decrypt = false;
  uint32_t dOffset = 0;
  uint32_t dSize = 0;
  for (int i = 2; i < argc; ++i)
  {
    if (std::string("-antiasm").compare(argv[i]) == 0)
      antiasm = true;
    else if (std::string("-bypass").compare(argv[i]) == 0)
      bypass = true;
    else if (std::string("-decrypt").compare(argv[i]) == 0)
    { //eg: -decrypt FF0 80
      if (i + 3 > argc)
      {
        printf("-decrypt requires offset and size args\n");
        return 0;
      }
      dOffset = strtoul(argv[i + 1], NULL, 16);
      dSize = strtoul(argv[i + 2], NULL, 16);
      decrypt = true;
      i += 2;
    }
  }

  if (antiasm && (bypass || decrypt))
  {
    printf("Cannot use -antiasm with -bypass or -decrypt\n");
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
    Analyzer::PatchSafeDiscAntiDisassembler(loader, SectionType::TXT2);
    Analyzer::PatchSafeDiscAntiDisassembler(loader, SectionType::TEXT);
  }

  if (bypass)
  {
    printf("Applying bypass patches\n");
    if (!ApplyPatches(loader))
      return 0;
  }

  bool result = loader.PatchPEFile(argv[1]);
  printf("Patch successful = %s\n", result ? "true" : "false");
  loader.Destroy();
  return 0;
}