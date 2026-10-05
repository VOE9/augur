/* OLD (already safe): the length guard returns early for short inputs, so
   the fixed-size copy only ever runs when at least 20 bytes are known to be
   present. ASan-verified clean at every truncation length of the seed. */
static char *parse_addr(const char *report, int index) {
  char addr[20];
  char idx[6];

  memset(idx, 0, 6);
  snprintf(idx, 6, "#%d ", index);
  char *pc = strstr(report, idx);
  if (pc == NULL) {
    return NULL;
  }
  pc += strlen(idx);

  if (strlen(pc) < 20) {
    return NULL;
  }
  memset(addr, 0, 20);
  memcpy(addr, pc, 20);
  addr[19] = '\0';
  return strdup(addr);
}