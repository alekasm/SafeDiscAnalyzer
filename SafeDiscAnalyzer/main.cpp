#include "PELoader.h"
#include "Analyzer.h"
#include "F18Patch.h"
#include <vector>
int main(int argc, const char** argv)
{
  if (argc < 2)
  {
    printf("Usage: ./SafeDiscAnalyzer.exe <file> <args>\nArguments:\n");
    printf("-antiasm\tpatches anti-disassembler routines\n");
    printf("-bypass\tapplies various patches to crack the game\n");
    return 0;
  }

  bool antiasm = false;
  bool bypass = false;
  for (int i = 2; i < argc; ++i)
  {
    if (std::string("-antiasm").compare(argv[i]) == 0)
      antiasm = true;
    else if (std::string("-bypass").compare(argv[i]) == 0)
      bypass = true;
  }

  PELoader loader;
  std::vector<SectionInfo> sections = {
    SectionInfo(".text"), SectionInfo(".txt2"), SectionInfo(".txt")
  };
  loader.LoadPEFile(argv[1], sections);
  for (const SectionInfo& section : sections)
  {
    if (!section.initialized)
    {
      printf("Unable to find section: %s\n", section.name);
      return 0;
    }
  }

  if (antiasm)
  {
    printf("Analyzing sections for anti-disassembler techniques\n");
    Analyzer analyzer;
    for (SectionInfo& section : sections)
      analyzer.PatchSafeDiscAntiDisassembler(section);
  }

  if (bypass)
  {
    printf("Applying F18 patches\n");
    ApplyF18Patches(sections);
  }

  bool result = loader.PatchPEFile(argv[1], sections);

  printf("Patch successful = %s\n", result ? "true" : "false");
  for (SectionInfo& section : sections)
    delete section.data;
  return 0;
}