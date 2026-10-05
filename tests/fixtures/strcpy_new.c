/* NEW (fixed): the copy is bounded by both the bytes available and the
   space in the destination, and the terminator is written inside the
   buffer rather than one past it. */
static char * parse_addr(const char *report, int index) {
  char addr[20];
  char idx[6];
  char *end;
  size_t rem;

  memset(idx, 0, 6);
  snprintf(idx, 6, "#%d ", index);
  char *pc = strstr(report, idx);
  if (pc == NULL) {
    return NULL;
  }
  pc += strlen(idx);

  rem = strlen(pc);
  if (rem > sizeof(addr) - 1) {
    rem = sizeof(addr) - 1;
  }
  memcpy(addr, pc, rem);
  addr[rem] = '\0';

  end = strchr(addr, ' ');
  if (end == NULL) {
    return NULL;
  }
  end[0] = '\0';
  return strdup(addr);
}