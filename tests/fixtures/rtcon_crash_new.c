#include <string.h>
#include <stdlib.h>

__attribute__((no_sanitize("coverage"), no_sanitize("address"))) static void *
getCrashAddress(const char *report, int index) {
  char addr[20];
  char index_str[6];

  memset(index_str, 0, 6);
  snprintf(index_str, 6, "#%d ", index);
  char *pc = strstr(report, index_str);
  if (pc == NULL) return NULL;
  pc += strlen(index_str);

  memset(addr, 0, 20);
  size_t pc_len = strlen(pc);
  size_t copy_len = pc_len < 19 ? pc_len : 19;
  memcpy(addr, pc, copy_len);

  char *end = strchr(addr, ' ');
  if (end != NULL) { end[0] = '\0'; } else { return NULL; }

  return (void *)strtoul(addr, NULL, 16);
}
