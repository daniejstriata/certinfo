#include <iostream>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/asn1.h>
#include <openssl/x509v3.h>
#include <iomanip>

// Function to get a string representation of ASN1_STRING
std::string ASN1_STRING_to_string(ASN1_STRING* asn1_string) {
    std::string result;
    unsigned char* utf8_str = nullptr;
    int length = ASN1_STRING_to_UTF8(&utf8_str, asn1_string);

    if (length > 0) {
        result.assign(reinterpret_cast<char*>(utf8_str), length);
        OPENSSL_free(utf8_str);
    }

    return result;
}

// Function to convert ASN1_TIME to a human-readable string
std::string ASN1_TIME_to_string(ASN1_TIME* asn1_time) {
    BIO* bio = BIO_new(BIO_s_mem());
    ASN1_TIME_print(bio, asn1_time);

    char* buf;
    size_t len = BIO_get_mem_data(bio, &buf);

    std::string result(buf, len);

    BIO_free(bio);
    return result;
}

// Function to process a certificate in the bundle
void processCertificate(X509* cert, int certNumber) {
    // Extract Common Name (CN)
    X509_NAME* subject_name = X509_get_subject_name(cert);
    int cn_index = X509_NAME_get_index_by_NID(subject_name, NID_commonName, -1);
    if (cn_index != -1) {
        X509_NAME_ENTRY* cn_entry = X509_NAME_get_entry(subject_name, cn_index);
        ASN1_STRING* cn_value = X509_NAME_ENTRY_get_data(cn_entry);
        std::cout << "\033[1m#" << certNumber << " - Common Name (CN):\033[0m " << ASN1_STRING_to_string(cn_value) << std::endl;
    } else {
        std::cout << "\033[1m#" << certNumber << " - Common Name (CN):\033[0m N/A" << std::endl;
    }

    // Extract Validity Dates
    ASN1_TIME* not_before = X509_get_notBefore(cert);
    ASN1_TIME* not_after = X509_get_notAfter(cert);

    std::string notAfterStr = ASN1_TIME_to_string(not_after);
    std::cout << "\t\033[33mValid from:\033[0m " << ASN1_TIME_to_string(not_before) << std::endl;

    // Check if the certificate has expired
    if (X509_cmp_time(not_after, 0) < 0) {
        std::cout << "\t\033[1;31mValid until:\033[0m \033[1;31m" << notAfterStr << " (Expired)\033[0m" << std::endl;
    } else {
        std::cout << "\t\033[33mValid until:\033[0m " << notAfterStr << std::endl;
    }

    // Extract Subject Alternative Names (SAN)
    GENERAL_NAMES* san_names = static_cast<GENERAL_NAMES*>(X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL));
    if (san_names) {
        for (int i = 0; i < sk_GENERAL_NAME_num(san_names); ++i) {
            GENERAL_NAME* san_entry = sk_GENERAL_NAME_value(san_names, i);
            if (san_entry->type == GEN_DNS) {
                std::cout << "\tSubject Alternative Name (SAN): " << ASN1_STRING_to_string(san_entry->d.dNSName) << std::endl;
            }
        }
        GENERAL_NAMES_free(san_names);
    }
}

void print_help(const char* program_name) {
    std::cout << "Usage: " << program_name << " <path_to_pem_bundle>" << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  --help     Display this help message" << std::endl;
    std::cout << "  --version  Display version information" << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        print_help(argv[0]);
        return 1;
    }

    if (argc == 2 && std::string(argv[1]) == "--help") {
        print_help(argv[0]);
        return 0;
    }

    if (argc == 2 && std::string(argv[1]) == "--version") {
        std::cout << "certinfo version 1.1.2" << std::endl;
        return 0;
    }

    const char* bundle_path = argv[1];
    FILE* bundle_file = fopen(bundle_path, "r");

    if (!bundle_file) {
        std::cerr << "Error opening file: " << bundle_path << std::endl;
        return 1;
    }

    X509* cert = nullptr;
    STACK_OF(X509)* cert_stack = sk_X509_new_null();
    int certNumber = 0;

    while ((cert = PEM_read_X509(bundle_file, NULL, NULL, NULL))) {
        sk_X509_push(cert_stack, cert);
        certNumber++;
    }

    fclose(bundle_file);

    if (sk_X509_num(cert_stack) == 0) {
        std::cerr << "No certificates found in the bundle" << std::endl;
        sk_X509_free(cert_stack);
        return 1;
    }

    // Process each certificate in the bundle
    for (int i = 0; i < sk_X509_num(cert_stack); ++i) {
        X509* current_cert = sk_X509_value(cert_stack, i);
        processCertificate(current_cert, i + 1);
    }

    // Cleanup
    sk_X509_free(cert_stack);

    return 0;
}
