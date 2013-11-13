#include <stdio.h>

#include "ping_linux.c"

int main(int argc, char **argv) {
  char **value = NULL;
  value = (char**)malloc(sizeof(char*));
  *value = NULL;
  int ret = ping(255, "8.8.8.8", 4, value);
  if (ret == 0) {
    printf("%s\n",*value);
  }
}
