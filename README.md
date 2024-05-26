# File Encryption

This project is designed to encrypt and decrypt files in a specified directory and its subdirectories using the AES-GCM encryption algorithm. The project supports concurrent file processing using goroutines and reads configuration settings from a `.env` file.

## Description

The project consists of two main components: encryption and decryption. It uses the AES-GCM encryption algorithm to ensure data security and integrity. The project is designed to handle large directories with multiple files efficiently by using goroutines for concurrent processing.

## Installation

1. Clone the repository:
   ```sh
   git clone https://github.com/vibhushit/file-encryption
   cd file-encryption

2. Install dependencies:
   ```sh
   go get github.com/joho/godotenv

3. Create a `.env` file in the project root directory with the following content:
    ```env
    SOURCE_DIR=C:\Users\Vibhu\Desktop\Projects\tata-ce\project_v3\sourceDir
    CLOUD_DIR=C:\Users\Vibhu\Desktop\Projects\tata-ce\project_v3\cloudDir
    DEST_DIR=C:\Users\Vibhu\Desktop\Projects\tata-ce\project_v3\destinationDir
    PASSWORD=password

## Usage

1. Run the main program:
   ```sh
   go run main.go

2. Follow the on-screen instructions to encrypt or decrypt files.
