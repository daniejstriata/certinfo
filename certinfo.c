#include <stdio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/asn1.h>
#include <openssl/bio.h>

#define PROGRAM_VERSION "1.0"

void print_certificate_info(X509 *cert) {
    X509_NAME *subject = X509_get_subject_name(cert);
    int cn_index = X509_NAME_get_index_by_NID(subject, NID_commonName, -1);

    if (cn_index >= 0) {
        X509_NAME_ENTRY *cn_entry = X509_NAME_get_entry(subject, cn_index);
        ASN1_STRING *cn_data = X509_NAME_ENTRY_get_data(cn_entry);

        // Print Common Name in bold
        printf("\033[1mCommon Name (CN):\033[0m %s\n", ASN1_STRING_data(cn_data));
    } else {
        printf("\033[1mCommon Name (CN) not found in the certificate.\033[0m\n");
    }

    // Extract Validity period
    ASN1_TIME *not_before = X509_get_notBefore(cert);
    ASN1_TIME *not_after = X509_get_notAfter(cert);

    // Convert ASN1_TIME to human-readable strings
    char not_before_str[256];
    char not_after_str[256];

    BIO *bio = BIO_new(BIO_s_mem());

    if (bio) {
        ASN1_TIME_print(bio, not_before);
        BIO_gets(bio, not_before_str, sizeof(not_before_str));

        ASN1_TIME_print(bio, not_after);
        BIO_gets(bio, not_after_str, sizeof(not_after_str));

        BIO_free(bio);
    }

    // Print Validity period with color and tab
    printf("\033[1;33m\tNot Before:\033[0m %s", not_before_str);  // Yellow with tab
    printf("\033[1;33m\tNot After: \033[0m %s", not_after_str);   // Yellow with tab

    printf("\n");
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <certificate_file>\n", argv[0]);
        return 1;
    }

    const char *cert_path = argv[1];
    FILE *file = fopen(cert_path, "r");

    if (!file) {
        perror("Error opening certificate file");
        return 1;
    }

    // Read each certificate from the bundle
    X509 *cert;
    while ((cert = PEM_read_X509(file, NULL, NULL, NULL)) != NULL) {
        // Print information for each certificate
        print_certificate_info(cert);

        // Free the current certificate
        X509_free(cert);
    }

    fclose(file);

    return 0;
}
