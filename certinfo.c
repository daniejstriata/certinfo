#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/asn1.h>
#include <openssl/x509v3.h>

// Structure to represent a certificate
struct Certificate {
    X509* cert;
};

// Function to get a string representation of ASN1_STRING
char* ASN1_STRING_to_string(ASN1_STRING* asn1_string) {
    char* result = NULL;
    int length = ASN1_STRING_to_UTF8((unsigned char**)&result, asn1_string);
    return result;
}

// Function to convert ASN1_TIME to a human-readable string
char* ASN1_TIME_to_string(ASN1_TIME* asn1_time) {
    BIO* bio = BIO_new(BIO_s_mem());
    ASN1_TIME_print(bio, asn1_time);

    char* buf;
    size_t len = BIO_get_mem_data(bio, &buf);

    char* result = (char*)malloc(len + 1);
    if (result) {
        memcpy(result, buf, len);
        result[len] = '\0';
    }

    BIO_free(bio);
    return result;
}

// Function to process a certificate in the bundle
void processCertificate(struct Certificate* cert, int certNumber) {
    // Extract Common Name (CN)
    X509_NAME* subject_name = X509_get_subject_name(cert->cert);
    int entry_count = X509_NAME_entry_count(subject_name);
    char* common_name = NULL;

    for (int i = 0; i < entry_count; ++i) {
        X509_NAME_ENTRY* entry = X509_NAME_get_entry(subject_name, i);
        ASN1_STRING* entry_value = X509_NAME_ENTRY_get_data(entry);

        // Check if the entry is for Common Name (CN)
        if (OBJ_obj2nid(X509_NAME_ENTRY_get_object(entry)) == NID_commonName) {
            common_name = ASN1_STRING_to_string(entry_value);
            break;
        }
    }

    if (common_name) {
        printf("#%d - Common Name (CN): \033[1m%s\033[0m\n", certNumber, common_name);
        OPENSSL_free(common_name);
    } else {
        printf("#%d - Common Name (CN): \033[1mN/A\033[0m\n", certNumber);
    }

    // Extract Validity Dates
    ASN1_TIME* not_before = X509_get_notBefore(cert->cert);
    ASN1_TIME* not_after = X509_get_notAfter(cert->cert);
    printf("\t\033[33mValid from:\033[0m %s\n", ASN1_TIME_to_string(not_before));

    // Check if the certificate has expired
    if (X509_cmp_time(not_after, 0) < 0) {
        printf("\t\033[1;31mValid until:\033[0m \033[1;31m%s (Expired)\033[0m\n", ASN1_TIME_to_string(not_after));
    } else {
        printf("\t\033[33mValid until:\033[0m %s\n", ASN1_TIME_to_string(not_after));
    }

    // Extract Subject Alternative Names (SAN)
    GENERAL_NAMES* san_names = (GENERAL_NAMES*)X509_get_ext_d2i(cert->cert, NID_subject_alt_name, NULL, NULL);
    if (san_names) {
        for (int i = 0; i < sk_GENERAL_NAME_num(san_names); ++i) {
            GENERAL_NAME* san_entry = sk_GENERAL_NAME_value(san_names, i);
            if (san_entry->type == GEN_DNS) {
                printf("\tSubject Alternative Name (SAN): %s\n", ASN1_STRING_to_string(san_entry->d.dNSName));
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

    // Read certificates from the PEM bundle
    STACK_OF(X509)* cert_stack = sk_X509_new_null();
    X509* cert = NULL;
    int certNumber = 0;

    while ((cert = PEM_read_X509(bundle_file, NULL, NULL, NULL))) {
        sk_X509_push(cert_stack, cert);
        certNumber++;
    }

    fclose(bundle_file);

    if (sk_X509_num(cert_stack) == 0) {
        fprintf(stderr, "No certificates found in the bundle\n");
        sk_X509_free(cert_stack);
        return 1;
    }

    // Process each certificate in the bundle
    for (int i = 0; i < sk_X509_num(cert_stack); ++i) {
        struct Certificate current_cert = { sk_X509_value(cert_stack, i) };
        processCertificate(&current_cert, i + 1);
    }

    // Cleanup
    sk_X509_free(cert_stack);

    return 0;
}
