#include <stdio.h>
#include <stdlib.h>
#include <string.h>


/*
WPA*01*PMKID*MAC_AP*MAC_CLIENT*ESSID***MESSAGEPAIR
WPA*02*MIC*MAC_AP*MAC_CLIENT*ESSID*NONCE_AP*EAPOL_CLIENT*MESSAGEPAIR
https://hashcat.net/wiki/doku.php?id=cracking_wpawpa2
*/

/*
 * Actually we only need PMKID, MAC_AP, MAC_CLIENT, ESSID
 */

struct wpa{
    struct {
        char *pmkid;
        char *mac_ap;
        char *mac_client;
        char *essid;
        char *messagepair;
    } wpa1;
    struct {
        char *mic;
        char *mac_ap;
        char *mac_client;
        char *essid;
        char *nonce_ap;
        char *eapol_client;
        char *messagepair;
    } wpa2;
};

void print_info(struct wpa *info) {
    printf("Data received from 22000 file: \n");
    printf("pmkid: %s\n", info->wpa1.pmkid);
    printf("ssid: %s\n", info->wpa1.essid);
    printf("mac_client: %s\n", info->wpa1.mac_client);
    printf("mac_ap: %s\n", info->wpa1.mac_ap);
    printf("\n");
}

void get_input(char *filename) {

}



int main(void) {
    FILE *fptr = fopen("./data/input.hc22000", "r");
    if (fptr == NULL) {
        exit(EXIT_FAILURE);
    }
    printf("File opened successfully\n");

    char * line = NULL;
    size_t len = 0;
    ssize_t wpa;

    while ((wpa = getline(&line, &len, fptr)) != -1) {
        printf("Retrieved line of length %zu:\n", wpa);
        printf("%s", line);

        char delimiter[] = "*";
        char *ptr;

        // initialisieren und ersten Abschnitt erstellen
        ptr = strtok(line, delimiter);

        while(ptr != NULL) {
            printf("Abschnitt gefunden: %s\n", ptr);
            // naechsten Abschnitt erstellen
            ptr = strtok(NULL, delimiter);
        }
    }
    fclose(fptr);
    if (line) {
        free(line);
    }
    return 0;
}
