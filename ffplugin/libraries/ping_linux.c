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
int32_t ping(unsigned char ttl, char* address, int32_t ipversion, char **ret) {
     *ret = malloc(sizeof(char));
     **ret = 0;
     int32_t pipes[2];
     pipe(pipes);
     char *ttlstring = malloc(MAXLINELENGTH * sizeof(char));
     snprintf(ttlstring, MAXLINELENGTH, "%d", ttl);
     char * args[] = {"/bin/ping", "-c", "1", "-n", "-W1", "-t", ttlstring, address, NULL};
     if (ipversion == 6) {
	  args[0] = "/bin/ping6";
     } else if (ipversion != 4) {
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
	  if (retval != 0) {
	       free(*ret);
	       *ret = NULL;
	  }
	  return retval;
     } else if (WIFSIGNALED(returnstatus)) {
	  int signal = WTERMSIG(returnstatus);
	  free(*ret);
	  *ret = NULL;
	  return -signal;
     } else {
	  return -1;
     }
}
