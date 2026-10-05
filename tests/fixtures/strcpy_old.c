/* OLD (vulnerable): strcpy into a fixed-size buffer from a pointer into
   caller-supplied data. Classic unbounded copy -- the shape the previous
   detector could not see at all, because it only understood memcpy. */
static char * parse_addr(const char *report, int index) {
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

  strcpy(addr, pc);

  end = strchr(addr, ' ');
  if (end == NULL) {
    return NULL;
  }
  end[0] = '\0';
  return strdup(addr);
}