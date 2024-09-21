#include <stdio.h>
#include <stdlib.h>

struct input{
    int version;
    char *pmkid;
    char *ssid;
    char *mac_client;
    char *mac_router;
};

void print_info(struct input *info) {
    printf("Data received from 22000 file: \n");
    printf("version: %d\n", info->version);
    printf("pmkid: %s\n", info->pmkid);
    printf("ssid: %s\n", info->ssid);
    printf("mac_client: %s\n", info->mac_client);
    printf("mac_router: %s\n", info->mac_router);
    printf("\n");
}

void get_input(char *filename) {
    FILE * fp;
    char * line = NULL;
    size_t len = 0;
    ssize_t read;

    fp = fopen(filename, "r");
    if (fp == NULL)
        exit(EXIT_FAILURE);

    while ((read = getline(&line, &len, fp)) != -1) {
        printf("Retrieved line of length %zu:\n", read);
        printf("%s", line);
    }

    fclose(fp);
    if (line)
        free(line);
    exit(EXIT_SUCCESS);
}



int main(void) {
    FILE *fptr = fopen("input.hc22000", "r");
    if (fptr == NULL)
        exit(EXIT_FAILURE);
    printf("File opened successfully\n");
    return 0;
}
