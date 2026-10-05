/* OLD (vulnerable): an unconditional fixed-size copy of 20 bytes out of a
   pointer into a caller-supplied string. ASan-verified heap-buffer-overflow
   whenever fewer than 20 bytes remain past the match. */
static char *parse_addr(const char *report, int index) {
  char addr[20];
  char idx[6];
  char *end;

  memset(idx, 0, 6);
  snprintf(idx, 6, "#%d ", index);
  char *pc = strstr(report, idx);
  if (pc == NULL) {
    return NULL;
  }
  pc += strlen(idx);

  memset(addr, 0, 20);
  memcpy(addr, pc, 20);

  end = strchr(addr, ' ');
  if (end == NULL) {
    return NULL;
  }
  end[0] = '\0';
  return strdup(addr);
}