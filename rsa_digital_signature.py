
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
import os
import getpass


PRIVATE_KEY_FILE = "private_key.pem"
PUBLIC_KEY_FILE = "public_key.pem"


def generate_keys():

    print("\nGenerating RSA keys...")

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    password = getpass.getpass("Set a password for private key: ").encode()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password)
    )

    with open(PRIVATE_KEY_FILE, "wb") as file:
        file.write(private_pem)

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(PUBLIC_KEY_FILE, "wb") as file:
        file.write(public_pem)

    print("\nRSA keys generated successfully!")


def load_private_key():

    if not os.path.exists(PRIVATE_KEY_FILE):
        print("Private key file not found!")
        return None

    password = getpass.getpass("Enter private key password: ").encode()

    try:
        with open(PRIVATE_KEY_FILE, "rb") as file:
            private_key_data = file.read()

        private_key = serialization.load_pem_private_key(
            private_key_data,
            password=password
        )

        return private_key

    except (ValueError, TypeError):
        print("Incorrect password or invalid private key!")
        return None


def load_public_key():

    if not os.path.exists(PUBLIC_KEY_FILE):
        print("Public key file not found!")
        return None

    try:
        with open(PUBLIC_KEY_FILE, "rb") as file:
            public_key_data = file.read()

        public_key = serialization.load_pem_public_key(
            public_key_data
        )

        return public_key

    except ValueError:
        print("Invalid public key!")
        return None


def calculate_hash(file_data):

    file_hash = hashes.Hash(hashes.SHA256())

    file_hash.update(file_data)

    digest = file_hash.finalize()

    return digest


def sign_file():

    file_path = input("Enter file path: ")

    if not os.path.isfile(file_path):
        print("File not found!")
        return

    private_key = load_private_key()

    if private_key is None:
        return

    try:
        with open(file_path, "rb") as file:
            file_data = file.read()

        digest = calculate_hash(file_data)

        signature = private_key.sign(
            file_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        signature_path = file_path + ".sig"

        with open(signature_path, "wb") as file:
            file.write(signature)

        print("\nFile signed successfully!")
        print("SHA-256:", digest.hex())
        print("Signature saved to:", signature_path)

    except OSError as error:
        print("File operation error:", error)


def verify_signature():

    file_path = input("Enter file path: ")

    if not os.path.isfile(file_path):
        print("File not found!")
        return

    signature_path = file_path + ".sig"

    if not os.path.isfile(signature_path):
        print("Signature file not found!")
        return

    public_key = load_public_key()

    if public_key is None:
        return

    try:
        with open(file_path, "rb") as file:
            file_data = file.read()

        with open(signature_path, "rb") as file:
            signature = file.read()

        digest = calculate_hash(file_data)

        public_key.verify(
            signature,
            file_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        print("\nSignature is VALID!")
        print("File integrity verified.")
        print("SHA-256:", digest.hex())

    except InvalidSignature:
        print("\nSignature is INVALID!")
        print("The file or signature may have been modified.")

    except OSError as error:
        print("File operation error:", error)


def main():

    while True:

        print("\n========== RSA DIGITAL SIGNATURE ==========")
        print("1. Generate RSA keys")
        print("2. Sign a file")
        print("3. Verify a signature")
        print("4. Exit")

        choice = input("\nChoose an option: ")

        if choice == "1":

            generate_keys()

        elif choice == "2":

            sign_file()

        elif choice == "3":

            verify_signature()

        elif choice == "4":

            print("Program closed.")
            break

        else:

            print("Invalid choice! Try again.")


if __name__ == "__main__":
    main()
