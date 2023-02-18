#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char* argv[]) {
    system("chown root excalator");
    system("chmod u+s excalator");

    if (argc == 2) {
        char cat_cmd[80];
        printf("%s\n", cat_cmd);
        sprintf(cat_cmd, "cat %s", argv[1]);

        system(cat_cmd);
    }
}