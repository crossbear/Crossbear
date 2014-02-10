// -*- c-file-style: "k&r"; -*-

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <locale.h>
#include <stdint.h>

#define MAXLINELENGTH 255

// For now we call the ping binary.
int32_t ping(uint8_t ttl,/* const */char* address, uint8_t ipversion, char **ret) {
     fprintf(stderr, "PING TTL: %d, Address: %s, IP version: %d\n", ttl, address, ipversion);
     if (ret == NULL) {
	  fprintf(stderr, "NULL pointer given as output value, quitting.");
	  return 2;
     }
     *ret = malloc(sizeof(char));
     **ret = 0;
     int32_t pipes[2];
     pipe(pipes);
     char *ttlstring = malloc(MAXLINELENGTH * sizeof(char));
     snprintf(ttlstring, MAXLINELENGTH, "%d", ttl);
     // TODO: Do initialization differently so we can use a const char.
     char * args[] = {NULL, "-c", "1", "-n", "-W1", "-t", ttlstring, address, NULL};
     if (ipversion == 6) {
	  args[0] = "/bin/ping6";
     } else if (ipversion == 4) {
	  args[0] = "/bin/ping";
     } else {
	  fprintf(stderr, "Invalid IP version. Got %d, expected 4 or 6.", ipversion);
	  free(ttlstring);
	  return 1;
     }
     pid_t childpid = fork();
     if (childpid == 0) {
	  close(pipes[0]);
	  // We leave stderr undupped, so we can see errors properly.
	  dup2(pipes[1], STDOUT_FILENO);
	  int32_t retval = execve(args[0], args, (char *const *)NULL);
	  if (retval < 0) {
	       fprintf(stderr, "Fork error: %s", strerror(errno));
	       free(ttlstring);
	       exit(255);
	  }
     }
     free(ttlstring);
     close(pipes[1]);
     FILE *input = fdopen(pipes[0], "r");
     int32_t totallength = 0;
     char *line = (char*)malloc(MAXLINELENGTH * sizeof(char));
     while (fgets(line, MAXLINELENGTH, input) != NULL) {
	  *ret = realloc(*ret,  totallength + strlen(line) + 1);
	  strncat(*ret, line, MAXLINELENGTH);
	  totallength = strlen(*ret);
	  memset(line, 0, MAXLINELENGTH);
     }
     free(line);
     fclose(input);
     int32_t returnstatus = 0;
     waitpid(childpid, &returnstatus, 0);
     if (WIFEXITED(returnstatus)) {
	  int retval = WEXITSTATUS(returnstatus);
	  return -retval;
     } else if (WIFSIGNALED(returnstatus)) {
	  int signal = WTERMSIG(returnstatus);
	  free(*ret);
	  *ret = NULL;
	  return -signal;
     } else {
	  return -1;
     }
}

#include <arpa/inet.h>

int32_t is_valid_ip(const char *addr) {
     // Enough room for the bigger of the two structures.
     void *tmpbuf = malloc(sizeof(struct in6_addr));
     int ret = inet_pton(AF_INET, addr, tmpbuf);
     if (ret == 1) {
	  free(tmpbuf);
	  return 1;
     } else if (ret == 0) {
	  ret =  inet_pton(AF_INET6, addr, tmpbuf);
	  free(tmpbuf);
	  return ret;
     } else {
	  return 1;
     }
}
