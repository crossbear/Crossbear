#include <stdio.h>

#include "ping_linux.c"

void test_ping(const char *address, uint8_t ipversion) {
  char **value = malloc(sizeof(char**));
  if (! ping(255, address, ipversion, value)) {
    printf("%s\n",*value);
  }
  free(*value);
  free(value);
}

void test_valid_ip() {
  printf("8.8.8.8 (should be valid): %d\n", is_valid_ip("8.8.8.8"));
  printf("fc00::3 (should be valid): %d\n", is_valid_ip("fc00::3"));
  printf("266.0.0.0 (should be invalid): %d\n", is_valid_ip("266.0.0.0"));
  printf("fc000:::0:3 (should be invalid): %d\n", is_valid_ip("fc000:::0:3"));
}

int main(int argc, char **argv) {
  test_ping("8.8.8.8",4);
  test_ping("2001:4860:4860::8888",6);
  test_valid_ip();
}
