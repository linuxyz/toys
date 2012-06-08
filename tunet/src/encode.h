#pragma once

#include <string.h>

static unsigned char arrayOfByte2[512];

char* Encode(const char *paramString1, const char *paramString2, char* out)
{
  int n = 0;
  int j = strlen(paramString1);
  int k = strlen(paramString2);
  int m = k - 1;
  int i;
  //unsigned char arrayOfByte2[256];
  //byte[] arrayOfByte3 = paramString1.getBytes();
  //byte[] arrayOfByte1 = paramString2.getBytes();
  for (i = 0; i < j; i++)
    {
      int i3;
      int i2 = (unsigned char)(paramString1[i] ^ paramString2[m]);
      int i1 = 0xF & i2 >> 4;
      i2 &= 15;
      i1 += 99;
      i2 += 54;
      if (m % 2 <= 0)
        i3 = i1;
      else
        i3 = i2;
      arrayOfByte2[n] = i3;
      n += 1;
      if (m % 2 <= 0)
        i1 = i2;
      else
        i1 = i1;
      arrayOfByte2[n] = i1;
      n += 1;
      m--;
      if (m >= 0)
        continue;
      m = k - 1;
    }
  arrayOfByte2[n] = 0;

  if (out)
    strncpy(out, arrayOfByte2, n+1);

  return arrayOfByte2;
}


