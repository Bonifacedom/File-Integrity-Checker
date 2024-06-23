import hashlib
import os


def calculate_sha256(file_path):
    """Calculate SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        # Read and update hash string value in blocks of 4K
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def main():
    print("File Integrity Checker using SHA-256")
    print("------------------------------------")

    # Get the file path from user input
    file_path = input("Enter the path to the file: ").strip()

    # Check if the file exists
    if not os.path.exists(file_path):
        print(f"Error: File '{file_path}' not found.")
        return

    # Calculate the SHA-256 hash of the file
    file_hash = calculate_sha256(file_path)

    print(f"SHA-256 hash of the file: {file_hash}")

    # Ask the user for the expected hash value
    expected_hash = input("Enter the expected SHA-256 hash value: ").strip()

    # Compare the calculated hash with the expected hash
    if file_hash == expected_hash:
        print("File integrity verified: Hashes match.")
    else:
        print("File integrity verification failed: Hashes do not match.")


if __name__ == "__main__":
    main()
