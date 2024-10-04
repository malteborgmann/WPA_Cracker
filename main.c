#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#define MAX_LINE 10240
#define MAX_PASSLIST 1000000
#define SIZE_ESSENTIALS 256
#define SIZE_MAC 18
#define SIZE_EAPOL 1024

struct wpa_hash {
    struct {
        char *pmkid;
        char *mac_ap;
        char *mac_client;
        char *essid;
    } wpa1;

    struct {
        char *mic;
        char *mac_ap;
        char *mac_client;
        char *essid;
        char *nonce_ap;
        char *eapol_client;
    } wpa2;
};

struct wpa_hash get_input(char *filepath);

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
            printf("Password Cracked!\033[0m\n\n");
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
    char *passlist_src = "passlist.txt";
    char *hc22000 = "./data/input.hc22000";

    struct wpa_hash hash = get_input(hc22000);

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

    unsigned char mac_ap[6], mac_cl[6];
    hex_to_bytes(hash.wpa1.mac_ap, mac_ap, 6);
    hex_to_bytes(hash.wpa1.mac_client, mac_cl, 6);

    if (!crack_pmkid(hash.wpa1.pmkid, (unsigned char*)hash.wpa1.essid, mac_ap, mac_cl, passlist, passlist_len)) {
        printf("Password not found in the list.\n");
    }

    // Free allocated memory
    for (int i = 0; i < passlist_len; i++) {
        free(passlist[i]);
    }

    // Free memory allocated for hash structure
    free(hash.wpa1.pmkid);
    free(hash.wpa1.mac_ap);
    free(hash.wpa1.mac_client);
    free(hash.wpa1.essid);
    free(hash.wpa2.mic);
    free(hash.wpa2.mac_ap);
    free(hash.wpa2.mac_client);
    free(hash.wpa2.essid);
    free(hash.wpa2.nonce_ap);
    free(hash.wpa2.eapol_client);

    return 0;
}

struct wpa_hash get_input(char *filepath) {
    struct wpa_hash hash;

    // Allocate memory for WPA1 fields
    hash.wpa1.pmkid = malloc(SIZE_ESSENTIALS);
    hash.wpa1.mac_ap = malloc(SIZE_MAC);
    hash.wpa1.mac_client = malloc(SIZE_MAC);
    hash.wpa1.essid = malloc(SIZE_ESSENTIALS);

    // Allocate memory for WPA2 fields
    hash.wpa2.mic = malloc(SIZE_ESSENTIALS);
    hash.wpa2.mac_ap = malloc(SIZE_MAC);
    hash.wpa2.mac_client = malloc(SIZE_MAC);
    hash.wpa2.essid = malloc(SIZE_ESSENTIALS);
    hash.wpa2.nonce_ap = malloc(SIZE_ESSENTIALS);
    hash.wpa2.eapol_client = malloc(SIZE_EAPOL);

    FILE *fptr = fopen(filepath, "r");
    if (fptr == NULL) {
        perror("Error opening file");
        exit(EXIT_FAILURE);
    }
    printf("File opened successfully\n");

    char *line = NULL;
    size_t len = 0;
    ssize_t wpa;

    while ((wpa = getline(&line, &len, fptr)) != -1) {
        printf("Retrieved line of length %zu:\n", wpa);
        printf("%s", line);

        char delimiter[] = "*";
        char *ptr;

        ptr = strtok(line, delimiter);
        ptr = strtok(NULL, delimiter);
        if (ptr != NULL) {
            if (strcmp(ptr, "01") == 0) {  // WPA1 (PMKID)
                ptr = strtok(NULL, delimiter);
                strcpy(hash.wpa1.pmkid, ptr);
                ptr = strtok(NULL, delimiter);
                strcpy(hash.wpa1.mac_ap, ptr);
                ptr = strtok(NULL, delimiter);
                strcpy(hash.wpa1.mac_client, ptr);
                ptr = strtok(NULL, delimiter);
                strcpy(hash.wpa1.essid, ptr);
            } else if (strcmp(ptr, "02") == 0) {  // WPA2 (MIC)
                ptr = strtok(NULL, delimiter);
                strcpy(hash.wpa2.mic, ptr);
                ptr = strtok(NULL, delimiter);
                strcpy(hash.wpa2.mac_ap, ptr);
                ptr = strtok(NULL, delimiter);
                strcpy(hash.wpa2.mac_client, ptr);
                ptr = strtok(NULL, delimiter);
                strcpy(hash.wpa2.essid, ptr);
                ptr = strtok(NULL, delimiter);
                strcpy(hash.wpa2.nonce_ap, ptr);
                ptr = strtok(NULL, delimiter);
                strcpy(hash.wpa2.eapol_client, ptr);
            }
        }
    }

    fclose(fptr);
    if (line) {
        free(line);
    }

    return hash;

}