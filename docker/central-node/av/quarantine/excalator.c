// Eleva i privilegi di se stesso ed esegue un comando arbitrario specificato dall'utente
// come argomento da CLI.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char* argv[]) {
    system("chown root excalator");
    system("chmod u+s excalator");

    if (argc == 2) {
        char usr_cmd[80];
        printf("%s\n", usr_cmd);
        sprintf(usr_cmd, "%s", argv[1]);

        system(usr_cmd);
    }
}
