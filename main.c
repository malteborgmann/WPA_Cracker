#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#define MAX_LINE 1024
#define MAX_PASSLIST 1000000

void hex_to_bytes(const char *hex, unsigned char *bytes, size_t len) {
    for (size_t i = 0; i < len; i++) {
        sscanf(hex + 2*i, "%2hhx", &bytes[i]);
    }
}

void print_hex(unsigned char *data, int len) {
    for (int i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int crack_pmkid(const unsigned char *pmkid, const unsigned char *essid, const unsigned char *mac_ap,
                const unsigned char *mac_cl, char **passlist, int passlist_len) {
    unsigned char pmk[32];
    unsigned char message[23] = "PMK Name";
    unsigned char hmac_result[32];
    unsigned int hmac_len;

    memcpy(message + 8, mac_ap, 6);
    memcpy(message + 14, mac_cl, 6);

    for (int i = 0; i < passlist_len; i++) {
        PKCS5_PBKDF2_HMAC_SHA1(passlist[i], strlen(passlist[i]), essid, strlen((char*)essid), 4096, 32, pmk);

        HMAC(EVP_sha1(), pmk, 32, message, 20, hmac_result, &hmac_len);

        if (memcmp(hmac_result, pmkid, 16) == 0) {
            printf("\033[92mPassword Cracked!\033[0m\n");
            printf("SSID:             %s\n", essid);
            printf("Password:         %s\n", passlist[i]);
            return 1;
        }
    }
    return 0;
}

int read_hc22000(const char *filename, unsigned char *pmkid, unsigned char *essid, unsigned char *mac_ap, unsigned char *mac_cl) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        printf("Could not open file %s\n", filename);
        return 0;
    }

    char line[MAX_LINE];
    if (fgets(line, sizeof(line), file) != NULL) {
        char *token = strtok(line, "*");
        if (token != NULL && strcmp(token, "WPA") == 0) {
            token = strtok(NULL, "*");
            token = strtok(NULL, "*");
            printf("Token: %s\n", token);
            if (token != NULL) {
                hex_to_bytes(token, pmkid, 16);
            }
            token = strtok(NULL, "*");
            if (token != NULL) {
                hex_to_bytes(token, mac_ap, 6);
            }
            token = strtok(NULL, "*");
            if (token != NULL) {
                hex_to_bytes(token, mac_cl, 6);
            }
            token = strtok(NULL, "*");
            if (token != NULL) {
                strncpy((char*)essid, token, strlen(token));
                essid[strlen(token)] = '\0';
            }
        }
    }

    fclose(file);
    return 1;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <hc22000_file> <passlist_file>\n", argv[0]);
        return 1;
    }

    char *hc22000_file = argv[1];
    char *passlist_file = argv[2];

    unsigned char pmkid[16];
    unsigned char essid[MAX_LINE];
    unsigned char mac_ap[6];
    unsigned char mac_cl[6];

    if (!read_hc22000(hc22000_file, pmkid, essid, mac_ap, mac_cl)) {
        return 1;
    }

    printf("Read from hc22000 file:\n");
    printf("PMKID: ");
    print_hex(pmkid, 16);
    printf("ESSID: %s\n", essid);
    printf("MAC AP: ");
    print_hex(mac_ap, 6);
    printf("MAC Client: ");
    print_hex(mac_cl, 6);

    char *passlist[MAX_PASSLIST];
    int passlist_len = 0;
    char line[MAX_LINE];
    FILE *file;

    // Read passlist file
    file = fopen(passlist_file, "r");
    if (file == NULL) {
        printf("Could not open file %s\n", passlist_file);
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