#include "Util.h"

unsigned char SecretHashValues[] = {
  0x9A, 0x09, 0x58, 0x53, 0x40, 0xF1, 0xF2, 0x93,
  0x40, 0xF1, 0xF2, 0x93, 0x40, 0xF1, 0xF2, 0x93,
};

void DecryptString(char* out, char* in)
{
  int count = 0;
  out[count] = in[count];

loop:
  char x = in[count];
  if (x == 0)
  {
    out[count] = 0;
    return;
  }
  count++;
  char i = in[count];
  i--;
  char j = out[count - 1];
  i ^= j;
  out[count] = i;
  goto loop;
}