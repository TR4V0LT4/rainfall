char *p(char *dest, char *s) {
  char buf[4104]; // [esp+10h] [ebp-1008h]
  puts(s);
  read(0, buf, 0x1000);
  *strchr(buf, 10) = 0;
  return strncpy(dest, buf, 0x14);
}

char *pp(char *dest) {
  char src[20]; // [esp+28h] [ebp-30h]
  char v3[28]; // [esp+3Ch] [ebp-1Ch]
  p(src, " - ");
  p(v3, " - ");
  strcpy(dest, src);
  *(_WORD *)&dest[strlen(dest)] = unk_80486A4; // Adds space
  return strcat(dest, v3);
}

int main(void) {
    char combined[54];

    // Read, combine, and print
    pp(combined);
    puts(combined);

    return 0;
}
