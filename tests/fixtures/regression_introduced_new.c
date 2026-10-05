/* NEW (a fix that introduced a crash): the defensive early-return guard was
   dropped during a refactor, leaving the unconditional 20-byte copy with
   nothing guaranteeing the source has that many bytes left. ASan-verified
   heap-buffer-overflow at the short truncation lengths at which the old
   version was clean. A "fix" like this is exactly the shape of change
   Augur exists to catch, so reporting it as anything other than a
   regression would be self-defeating. */
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

  memset(addr, 0, 20);
  memcpy(addr, pc, 20);
  addr[19] = '\0';
  return strdup(addr);
}