#include "Crypt.h"

uint32_t CreateNextDecryptionSkewFromText(PELoader& loader)
{
  SectionInfo& info_reloc = loader.GetSectionMap().at(SectionType::RELO2);
  SectionInfo& info_text = loader.GetSectionMap().at(SectionType::TEX2);
  SectionInfo& info_txt = loader.GetSectionMap().at(SectionType::TXT);
  SectionInfo& info_txt2 = loader.GetSectionMap().at(SectionType::TXT2);


  std::vector<RelocationData> reloc_data = loader.GetTextCopyRelocations();
  if (reloc_data.empty())
  {
    printf("Failed to decrypt, relocation data is empty\n");
    return 0;
  }

  uint32_t NextSkew = 0;


  //NextSkew = 0;
  unsigned int size_data = info_text.header.SizeOfRawData;
  unsigned int text_index = 0;
  int reloc_index = 0;

  uint32_t reloc_entry = reloc_data.at(reloc_index).entry;
  uint32_t reloc_offset = reloc_data.at(reloc_index).offset;
  uint32_t virtual_address_entry = 0;
  memcpy(&virtual_address_entry, &info_reloc.data[reloc_offset], 4);
  if (virtual_address_entry != reloc_entry)
  {
    printf("Raw Data Pointer: 0x%X\n", info_reloc.header.PointerToRawData);
    return 0;
  }

  uint32_t reloc_table = reloc_offset + 8;
  unsigned int table_index = reloc_table;
  unsigned short last_index = 0;
  unsigned int size_data_iter = size_data;
  unsigned int text_offset = 0;
  bool last_index_override = false;
  bool page_skip = false;
  if (size_data_iter > 0x1000)
    size_data_iter = 0x1000;

  //its possible to skip over relocation chunks
  while (size_data > 0)
  {


    //Function:0x4136A0
    unsigned short index_entry;
    memcpy(&index_entry, &info_reloc.data[table_index], 2);
    unsigned short index_upper = index_entry >> 0xC;
    unsigned short next_index = index_entry & 0xFFF;
    unsigned int current_index = 0;
    unsigned int true_last_index = last_index;
    switch (index_upper)
    {
    case 1:
    case 2:
      current_index = last_index + 2;
      break;
    case 3:
    case 4:
    case 5:
      current_index = last_index + 4;
      break;
    default:
      current_index = last_index + 0;
    }
    unsigned int size_count = next_index;
    unsigned int text_index = 0;
    if (current_index == last_index)
      current_index += 4;
    if (last_index > 0 || last_index_override)
    {
      size_count = size_count - current_index;
      text_index = current_index;
      last_index_override = false;
    }
    else
    {
      text_index = 0;
    }
    text_index += text_offset;

    if (next_index == 0)
    {
      if (size_data - size_data_iter > 0)
      { //table switch condition
        uint32_t switch_current_index = last_index + 4;
        text_index += switch_current_index - current_index;
        current_index = switch_current_index;
      }
      size_count = ((size_data_iter - 1) - current_index) + 1;
    }

    if (page_skip)
    {
      page_skip = false;
      current_index = 0;
      size_count = 0x1000;
      next_index = 0;
      index_upper = 0;
      last_index = -1;
    }

#ifdef DEBUGGING_ENABLED
    printf("[0x%X] entry<0x%X,0x%X> Decrypting 0x%X with size of 0x%X, ending: 0x%X, last=0x%X, current = 0x%X\n",
      table_index + info_reloc.header.PointerToRawData,
      next_index, index_upper,
      current_index, size_count, next_index,
      last_index, current_index);
    fflush(stdout);
#endif

    if (last_index == 0 && next_index == 0)
    {
#ifdef DEBUGGING_ENABLED
      printf("Skipped - likely starting new page on zero offset\n");
      fflush(stdout);
#endif
      current_index = 0;
      table_index = table_index + 2;
      last_index_override = true;
      continue;
    }
    last_index = next_index;

    //bool last_decrypt = false;
    if (next_index == 0)
    {
      if (size_data - size_data_iter > 0)
      {
        uint32_t old_reloc_entry = reloc_entry;
        ++reloc_index;

        //Verification Part 1
        if (reloc_index >= reloc_data.size())
        {
          printf("Relocation data only has %ld entries, attempting to grab entry %ld\n",
            reloc_index, reloc_data.size());
          return 0;
        }

        //Verification Part 2
        reloc_entry = reloc_data.at(reloc_index).entry;
        reloc_offset = reloc_data.at(reloc_index).offset;
        virtual_address_entry = 0;
        memcpy(&virtual_address_entry, &info_reloc.data[reloc_offset], 4);
        fflush(stdout);
        if (virtual_address_entry != reloc_entry)
        {
          printf("RelocationData Entry: 0x%X, RelocationTable Entry: 0x%X\n",
            reloc_entry, virtual_address_entry);
          printf("Raw Data Pointer: 0x%X\n", info_reloc.header.PointerToRawData);
          fflush(stdout);
          return 0;
        }
        uint32_t size_difference = (reloc_entry - old_reloc_entry);

        if (size_difference > 0x1000)
        { //page skip still gets processed
          reloc_entry = old_reloc_entry + 0x1000;
          --reloc_index;
          reloc_offset = reloc_data.at(reloc_index).offset;
          page_skip = true;
        }
        size_data -= (reloc_entry - old_reloc_entry);

        reloc_table = reloc_offset + 8;
#ifdef DEBUG_INTERMEDIATE_RELOCATION_SKEW
        printf("[%d] Switching to new table: 0x%X (File Offset=0x%X), Size Remaining: 0x%X\n",
          reloc_index, reloc_entry, reloc_offset + info_reloc.header.PointerToRawData, size_data);
        fflush(stdout);
#endif
      }
      else
      {
        //last_decrypt = true;
        size_data = 0;
      }


      table_index = reloc_table;
      last_index = 0;
      unsigned int old_iter = size_data_iter;
      if (size_data > 0x1000)
        size_data_iter = 0x1000;
      else
        size_data_iter = size_data;


#ifdef DEBUGGING_ENABLED
      printf("size remaining: 0x%X, iter: 0x%X\n", size_data, size_data_iter);
      fflush(stdout);
#endif
      text_offset += old_iter;
    }
    else
    {
      table_index = table_index + 2;
    }

    if (size_count == 0)
    {
#ifdef DEBUGGING_ENABLED
      printf("Size is zero - skipping\n");
      fflush(stdout);
#endif
      continue;
    }

    unsigned int starting_val = 0xFD379AB1;
    for (unsigned int j = size_count; j > 0; j--)
    {
      unsigned int v1 = info_text.data[text_index++] & 0xFF;
      v1 = v1 * starting_val;
      NextSkew += v1;
      unsigned int v2 = starting_val * 0xA7753394;
      starting_val = v2 + (j - 1) + 0x3BC62BB2;
    }

#ifdef DEBUG_INTERMEDIATE_RELOCATION_SKEW
    printf("Next Skew: 0x%X\n", NextSkew);
    fflush(stdout);
#endif
  }

#ifdef DEBUG_INTERMEDIATE_RELOCATION_SKEW
  printf("Final decryption skew: 0x%X\n", NextSkew);
  fflush(stdout);
#endif

  printf("Generated relocation text hash: 0x%X\n", NextSkew);
  return NextSkew;
}

void Decrypt(PELoader& loader, uint32_t showOffset, uint32_t showSize)
{
  SectionInfo& info_reloc = loader.GetSectionMap().at(SectionType::RELO2);
  SectionInfo& info_text = loader.GetSectionMap().at(SectionType::TEX2);
  SectionInfo& info_txt = loader.GetSectionMap().at(SectionType::TXT);
  SectionInfo& info_txt2 = loader.GetSectionMap().at(SectionType::TXT2);

  if (showOffset + showSize > info_txt.header.Misc.VirtualSize)
  {
    unsigned long vaddr = loader.GetImageBase() + info_txt.header.VirtualAddress;
    printf("Decryption 0x%08X - 0x%08X is outside of .txt section 0x%08X - 0x%08X\n",
      vaddr + showOffset, vaddr + showOffset + showSize,
      vaddr, vaddr + info_txt.header.Misc.VirtualSize);
    return;
  }

  std::vector<RelocationData> reloc_data = loader.GetTextCopyRelocations();
  if (reloc_data.empty())
  {
    printf("Failed to decrypt, relocation data is empty\n");
    return;
  }

  //txt section is the encrypted data that needs to be decrypted.
  //First pass prepares the encrypted txt section, xor with a rolling key - 8 bytes
  //The second pass xors with the txt2 section, and uses the secdrv kernel key every 16 bytes
  //Third pass will update the skew value as a result from the text section
  //Can verify this in .rdata +C, + 10 - consistent at least across Jane's F18
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

  unsigned int NextSkew = CreateNextDecryptionSkewFromText(loader);
  unsigned int size = info_txt.header.SizeOfRawData;
  char* decrypt_buffer = new char[size];
  memset(decrypt_buffer, 0, size);
  printf("Decrypting size of .txt: 0x%lx\n", size);


  for (unsigned int index = 0; index < size; index += 8)
  {
    const unsigned int init_val1 = *((unsigned int*)&info_txt.data[index + 0]);
    const unsigned int init_val2 = *((unsigned int*)&info_txt.data[index + 4]);
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
  }

  //0x421B38 - DecryptXORSections
  unsigned int decryption_skew = 0;
  unsigned int txt_size_remaining = info_txt.header.SizeOfRawData;
  unsigned int txt2_size_remaining = info_txt2.header.SizeOfRawData;
  unsigned int size_chunk = 0x1000;
  unsigned int info_txt2_offset = 0;
  unsigned int info_txt_offset = 0;
  bool switched = false;
  for (unsigned int i = 0; i < size; ++i)
  {

    if ((info_txt2_offset + 1) > info_txt2.header.SizeOfRawData)
    {
      info_txt2_offset = (info_txt2.header.SizeOfRawData - 0x1000);
    }

    decrypt_buffer[i] ^= (decryption_skew >> 0);
    decrypt_buffer[i] ^= (decryption_skew >> 8);
    decrypt_buffer[i] ^= (decryption_skew >> 16);
    decrypt_buffer[i] ^= (decryption_skew >> 24);
    decrypt_buffer[i] ^= info_txt2.data[info_txt2_offset];
    decryption_skew += decrypt_buffer[i] & 0xFF;

#ifdef DEBUGGING_ENABLED
    printf("Decryption Skew: 0x%X\n", decryption_skew);

#endif

    if ((i + 1) % 0x10 == 0) //421DB9
      decryption_skew += 0x400; //dr7 result from secdrv driver

    if ((i + 1) % 0x1000 == 0)
    {

      decryption_skew += NextSkew;
      txt_size_remaining -= size_chunk;
      txt2_size_remaining -= size_chunk;
      size_chunk = 0x1000 % txt_size_remaining;
      if (txt_size_remaining < 0x1000)
        info_txt2_offset = -1;
    }
    ++info_txt2_offset;
  }

  unsigned long vaddr = loader.GetImageBase() + info_txt.header.VirtualAddress;
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

