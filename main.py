from encryption import Encryption
import argparse


def main():
    parser = argparse.ArgumentParser(
        description="Encrypt and decrypt messages within CLI."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Show public key
    subparsers.add_parser("show-public", help="Display your public key")

    # Send message
    send_parser = subparsers.add_parser("send", help="Encrypt and send a message")
    send_parser.add_argument(
        "--recipient-key",
        required=True,
        help="Recipient's public key (PEM string or file path)",
    )
    send_parser.add_argument(
        "--message", required=True, help="Message to encrypt and send"
    )

    # Receive message
    recv_parser = subparsers.add_parser("receive", help="Decrypt a received message")
    recv_parser.add_argument(
        "--encrypted-message", required=True, help="Encrypted message (base64 string)"
    )
    recv_parser.add_argument(
        "--encrypted-key", required=True, help="Encrypted symmetric key (base64 string)"
    )
    recv_parser.add_argument(
        "--output-file", required=False, help="File to write the decrypted message to"
    )

    args = parser.parse_args()
    encrypt = Encryption()

    if args.command == "show-public":
        print(encrypt.own_pem_public_key.decode("utf-8").replace("\n", "\\n"))

    elif args.command == "send":
        # Load recipient key from file if needed
        recipient_key = args.recipient_key
        try:
            # Try to read as file path
            with open(recipient_key, "r") as f:
                recipient_key = f.read()
                print(f"Loaded recipient key from {args.recipient_key}")
        except FileNotFoundError:
            # If not a file, assume it's a PEM string
            print("Using provided recipient key directly.")
            pass

        # Load message from file if needed
        message = args.message
        try:
            with open(message, "r") as f:
                message = f.read()
                print(f"Loaded message from {args.message}")
        except FileNotFoundError:
            print("Using provided message directly.")
            pass  # Use as direct string

        encrypted_message, encrypted_symmetric_key = encrypt.send_message(
            message, recipient_key
        )

        print("\nEncrypted message:\n", encrypted_message.decode("utf-8"))
        print("\n\nEncrypted symmetric key:\n", encrypted_symmetric_key)

    elif args.command == "receive":
        # Load recipient key from file if needed
        encrypted_key = args.encrypted_key
        try:
            # Try to read as file path
            with open(encrypted_key, "r") as f:
                encrypted_key = f.read()
                print(f"Loaded recipient key from {args.encrypted_key}")
        except FileNotFoundError:
            # If not a file, assume it's a PEM string
            print("Using provided encryptedkey directly.")
            pass

        # Load message from file if needed
        encrypted_message = args.encrypted_message
        try:
            with open(encrypted_message, "r") as f:
                encrypted_message = f.read()
                print(f"Loaded encrypted message from {args.encrypted_message}")
        except FileNotFoundError:
            print("Using provided message directly.")
            pass  # Use as direct string

        message = encrypt.receive_message(encrypted_message, encrypted_key)

        if args.output_file:
            with open(args.output_file, "w") as f:
                f.write(message)
            print(f"Decrypted message written to {args.output_file}")
        else:
            print("Decrypted message:\n", message)


if __name__ == "__main__":
    main()
