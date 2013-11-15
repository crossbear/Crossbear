#include <stdio.h>

#include "ping_linux.c"

int main(int argc, char **argv) {
  char **value = malloc(sizeof(char**));
  if (! ping(255, "8.8.8.8", 4, value)) {
      printf("%s\n",*value);
  }
  free(*value);
  free(value);
}
