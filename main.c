#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#define SIZE_MAC 18
#define SIZE_ESSENTIALS 33
#define SIZE_EAPOL 68 // Arbitrary size for EAPOL

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
        printf("%s\n", line);

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

void get_hash(char *string) {


}

int main(void) {

    const char *password = "wireshark";  // The password
    const unsigned char *essid = (unsigned char *)"ikeriri-5g";  // The ESSID (salt)
    int iterations = 4096;  // Number of iterations
    int key_length = 32;  // Output key length (32 bytes for PMK)
    const unsigned char *mac_ap = (unsigned char *)"500f807018d0";  // MAC of the AP
    const unsigned char *mac_cl = (unsigned char *)"4040a75073db";  // MAC of the client

    unsigned char key[key_length];

    // Perform PBKDF2-HMAC-SHA256
    unsigned char pmk[key_length];
    if (PKCS5_PBKDF2_HMAC(password, strlen(password), essid, strlen((char *)essid), iterations, EVP_sha1(), key_length, pmk) == 0) {
        printf("Error deriving PMK.\n");
        return 1;
    }

    // Print derived key in hexadecimal format
    printf("Derived key: ");
    for (int i = 0; i < key_length; i++) {
        printf("%02x", key[i]);
    }
    printf("\n");


    return 0;

    /*char filepath [] = "./data/input.hc22000";
    struct wpa_hash hash = get_input(filepath);

    // Output WPA1 data if present
    printf("\nWPA1 Data:\n");
    printf("PMKID: %s\n", hash.wpa1.pmkid);
    printf("MAC AP: %s\n", hash.wpa1.mac_ap);
    printf("MAC Client: %s\n", hash.wpa1.mac_client);
    printf("ESSID: %s\n", hash.wpa1.essid);

    // Output WPA2 data if present
    printf("\nWPA2 Data:\n");
    printf("MIC: %s\n", hash.wpa2.mic);
    printf("MAC AP: %s\n", hash.wpa2.mac_ap);
    printf("MAC Client: %s\n", hash.wpa2.mac_client);
    printf("ESSID: %s\n", hash.wpa2.essid);
    printf("Nonce AP: %s\n", hash.wpa2.nonce_ap);
    printf("EAPOL Client: %s\n", hash.wpa2.eapol_client);

    // Free allocated memory for WPA1
    free(hash.wpa1.pmkid);
    free(hash.wpa1.mac_ap);
    free(hash.wpa1.mac_client);
    free(hash.wpa1.essid);

    // Free allocated memory for WPA2
    free(hash.wpa2.mic);
    free(hash.wpa2.mac_ap);
    free(hash.wpa2.mac_client);
    free(hash.wpa2.essid);
    free(hash.wpa2.nonce_ap);
    free(hash.wpa2.eapol_client);

    return 0;*/
}