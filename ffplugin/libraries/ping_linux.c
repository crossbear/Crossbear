// -*- c-file-style: "k&r"; -*-

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <locale.h>

#define MAXLINELENGTH 255

// For now we call the ping binary.
int ping(unsigned char ttl, char* address, int ipversion, char **ret) {
     // Don't rightly know if we need this.
     char *oldlocale = setlocale(LC_ALL, "");
     setlocale(LC_ALL, "C");
     int pipes[2];
     pipe(pipes);
     char *ttlstring = malloc(MAXLINELENGTH * sizeof(char));
     snprintf(ttlstring, MAXLINELENGTH, "%d", ttl);
     char *args[] = {"/bin/ping", "-c", "1", "-n", "-W1", "-t", ttlstring, address, NULL};
     if (ipversion == 6) {
	  args[0] = "/bin/ping6";
     } else if (ipversion != 4) {
	  fprintf(stderr, "Invalid IP version. Got %d, expected 4 or 6.", ipversion);
	  *ret = NULL;
	  return 1;
     }
     pid_t childpid = fork();
     if (childpid == 0) {
	  close(pipes[0]);
	  // We leave stderr undupped, so we can see errors properly.
	  dup2(pipes[1], STDOUT_FILENO);
	  int retval = execve(args[0], args, (char *const *)NULL);
	  if (retval < 0) {
	       fprintf(stderr, "Fork error: %s", strerror(errno));
	       exit(255);
	  }
     }
     close(pipes[1]);
     FILE *input = fdopen(pipes[0], "r");
     int totallength = 0;
     char *line = (char*)malloc(MAXLINELENGTH * sizeof(char));
     while (fgets(line, MAXLINELENGTH, input) != NULL) {
	  *ret = realloc(*ret,  totallength + strlen(line) + 1);
	  strcat(*ret, line);
	  totallength = strlen(*ret);
	  memset(line, 0, MAXLINELENGTH);
     }
     free(line);
     int returnstatus = 0;
     waitpid(childpid, &returnstatus, 0);
     if (! WIFEXITED(returnstatus)) {
	  free(*ret);
	  free(ttlstring);
	  return WEXITSTATUS(returnstatus);
     }
     setlocale(LC_ALL, oldlocale);
     free(ttlstring);
     return 0;
}
