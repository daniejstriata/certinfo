#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/asn1.h>
#include <openssl/x509v3.h>

#define MAX_CERTS 100
#define MAX_STRING_LENGTH 256

// Function to convert ASN1_TIME to a human-readable string
void ASN1_TIME_to_string(const ASN1_TIME* asn1_time, char* result, size_t result_size) {
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
        snprintf(result, result_size, "Error creating BIO");
        return;
    }
    
    if (!ASN1_TIME_print(bio, asn1_time)) {
        snprintf(result, result_size, "Error printing ASN1_TIME");
        BIO_free(bio);
        return;
    }

    int len = BIO_read(bio, result, result_size - 1);
    result[len] = '\0';
    BIO_free(bio);
}

// Function to process a certificate in the bundle
void processCertificate(X509* cert, int certNumber) {
    char buffer[MAX_STRING_LENGTH];
    
    // Extract Common Name (CN)
    X509_NAME* subject_name = X509_get_subject_name(cert);
    int common_name_index = X509_NAME_get_index_by_NID(subject_name, NID_commonName, -1);
    if (common_name_index >= 0) {
        X509_NAME_ENTRY* common_name_entry = X509_NAME_get_entry(subject_name, common_name_index);
        ASN1_STRING* common_name_asn1 = X509_NAME_ENTRY_get_data(common_name_entry);
        int len = ASN1_STRING_length(common_name_asn1);
        const unsigned char* data = ASN1_STRING_get0_data(common_name_asn1);
        snprintf(buffer, sizeof(buffer), "%.*s", len, data);
        printf("#%d - Common Name (CN): \033[1m%s\033[0m\n", certNumber, buffer);
    } else {
        printf("#%d - Common Name (CN): \033[1mN/A\033[0m\n", certNumber);
    }

    // Extract Validity Dates
    const ASN1_TIME* not_before = X509_get0_notBefore(cert);
    const ASN1_TIME* not_after = X509_get0_notAfter(cert);
    
    ASN1_TIME_to_string(not_before, buffer, sizeof(buffer));
    printf("\t\033[33mValid from:\033[0m %s\n", buffer);

    ASN1_TIME_to_string(not_after, buffer, sizeof(buffer));
    // Check if the certificate has expired
    if (X509_cmp_current_time(not_after) < 0) {
        printf("\t\033[1;31mValid until:\033[0m \033[1;31m%s (Expired)\033[0m\n", buffer);
    } else {
        printf("\t\033[33mValid until:\033[0m %s\n", buffer);
    }

    // Extract Subject Alternative Names (SAN)
    GENERAL_NAMES* san_names = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
    if (san_names) {
        for (int i = 0; i < sk_GENERAL_NAME_num(san_names); ++i) {
            GENERAL_NAME* san_entry = sk_GENERAL_NAME_value(san_names, i);
            if (san_entry->type == GEN_DNS) {
                ASN1_STRING* dns_name = san_entry->d.dNSName;
                int len = ASN1_STRING_length(dns_name);
                const unsigned char* data = ASN1_STRING_get0_data(dns_name);
                printf("\tSubject Alternative Name (SAN): %.*s\n", len, data);
            }
        }
        GENERAL_NAMES_free(san_names);
    }
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <path_to_pem_bundle>\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "--version") == 0) {
        printf("certinfo version 1.1\n");
        return 0;
    }

    const char* bundle_path = argv[1];
    FILE* bundle_file = fopen(bundle_path, "r");

    if (!bundle_file) {
        fprintf(stderr, "Error opening file: %s\n", bundle_path);
        return 1;
    }

    X509* certs[MAX_CERTS];
    int cert_count = 0;

    while (cert_count < MAX_CERTS) {
        X509* cert = PEM_read_X509(bundle_file, NULL, NULL, NULL);
        if (!cert) break;
        certs[cert_count++] = cert;
    }

    fclose(bundle_file);

    if (cert_count == 0) {
        fprintf(stderr, "No certificates found in the bundle\n");
        return 1;
    }

    for (int i = 0; i < cert_count; ++i) {
        processCertificate(certs[i], i + 1);
        X509_free(certs[i]);
    }

    return 0;
}
