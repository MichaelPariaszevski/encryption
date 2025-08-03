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
        except FileNotFoundError:
            # If not a file, assume it's a PEM string
            pass

        encrypted_message, encrypted_symmetric_key = encrypt.send_message(
            args.message, recipient_key
        )

        print("\nEncrypted message:\n", encrypted_message.decode("utf-8"))
        print("\n\nEncrypted symmetric key:\n", encrypted_symmetric_key)

    elif args.command == "receive":
        message = encrypt.receive_message(args.encrypted_message, args.encrypted_key)
        print("Decrypted message:\n", message)


if __name__ == "__main__":
    main()
