/* NEW (PARTIALLY fixed): the over-read itself is genuinely fixed -- the copy
   is clamped to the bytes that actually remain -- but the terminator write
   carries an off-by-one. When `rem` is clamped to exactly 20, `addr[20]` is
   one past the end of a char[20]. This is a real bug in this exact fix shape,
   and it only fires when 20 or more bytes remain -- i.e. at strictly LONGER
   inputs than the old crash needs. So the new version is clean at short
   lengths while the old one already crashes there, and still crashes at
   every longer length.

   Consequence for a differential harness: "the new version did not crash at
   the length where the old version first crashed" is true here, and yet the
   new version is not safe. Verifying only that one length is not enough. */
static char *parse_addr(const char *report, int index) {
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

  memset(addr, 0, 20);
  rem = strlen(pc);
  if (rem >= 20) {
    rem = 20;
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