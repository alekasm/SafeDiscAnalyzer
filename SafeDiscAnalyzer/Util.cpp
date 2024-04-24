#include "Util.h"

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