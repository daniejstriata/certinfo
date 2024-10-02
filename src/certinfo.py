import sys
from datetime import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.backends import default_backend

def process_certificate(cert, cert_number):
    # Extract Common Name
    try:
        common_name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        print(f"#{cert_number} - Common Name (CN): \033[1m{common_name}\033[0m")
    except IndexError:
        print(f"#{cert_number} - Common Name (CN): \033[1mN/A\033[0m")

    # Extract Validity Dates
    not_before = cert.not_valid_before
    not_after = cert.not_valid_after
    now = datetime.utcnow()

    print(f"\t\033[33mValid from:\033[0m {not_before.strftime('%b %d %H:%M:%S %Y GMT')}")
    
    if now > not_after:
        print(f"\t\033[1;31mValid until:\033[0m \033[1;31m{not_after.strftime('%b %d %H:%M:%S %Y GMT')} (Expired)\033[0m")
    else:
        print(f"\t\033[33mValid until:\033[0m {not_after.strftime('%b %d %H:%M:%S %Y GMT')}")

    # Extract Subject Alternative Names
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        for name in san.value:
            if isinstance(name, x509.DNSName):
                print(f"\tSubject Alternative Name (SAN): {name.value}")
    except x509.extensions.ExtensionNotFound:
        pass

    print()  # Add a blank line between certificates

def main(bundle_path):
    with open(bundle_path, 'rb') as file:
        pem_data = file.read()

    cert_number = 1
    start = 0
    while start < len(pem_data):
        end = pem_data.find(b'-----END CERTIFICATE-----', start)
        if end == -1:
            break
        end += len(b'-----END CERTIFICATE-----')
        
        try:
            cert = x509.load_pem_x509_certificate(pem_data[start:end], default_backend())
            process_certificate(cert, cert_number)
            cert_number += 1
        except ValueError:
            pass  # Invalid certificate, skip it
        
        start = pem_data.find(b'-----BEGIN CERTIFICATE-----', end)
        if start == -1:
            break

    if cert_number == 1:
        print("No valid certificates found in the bundle.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <path_to_pem_bundle>")
        sys.exit(1)

    if sys.argv[1] == "--version":
        print("certinfo version 1.1")
        sys.exit(0)

    main(sys.argv[1])
