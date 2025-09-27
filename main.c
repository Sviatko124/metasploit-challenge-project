// This is an intentionally vulnerable program to go along with my Metasploit module. Do not run this program in any environment that is not supposed to be vulnerable!
// To compile: gcc main.c -o dateservice.elf 
// To expose the program to the network: ncat -lnvp 6363 -e dateservice.elf -k

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    char username[20];

    printf("DateService v1.0.0\n==========\nWhat is your name: ");
    fflush(stdout);

    scanf("%256[^\n]", username); // for safety should be %19, to account for the null terminator and to avoid segmentation fault
	
    size_t len = strlen(username);
    if (len > 0 && username[len - 1] == '\n') {
        username[len - 1] = '\0';
    }

    char command[1024];
    snprintf(command, sizeof(command), "echo 'Hello %s, here is the date:'; date", username);

    system(command); // for safety should be fork() or equivalent, to run the date binary directly instead of allowing the user to run injected commands

    return 0;
}

