# Image Encryption using AES

This project demonstrates image encryption using the Advanced Encryption Standard (AES) algorithm.
By providing a simple console application that encrypts and decrypts images, 
this program showcases a symmetric-key block cipher encryption for visual data protection on large image datasets.

## Table of Contents

1. [Introduction](#introduction)
2. [Features](#features)
3. [Usage](#usage)
4. [Code Structure](#code-structure)
5. [Contributing](#contributing)


## Introduction

Image Encryption using AES is a C++ program designed to encrypt images using both sequential and parallel versions of the AES encryption algorithm.
This project was designed to apply AES encryption to a public image dataset in order demonstrate the difference between sequential encryption and parallel encryption.
Furthermore, the project utilizes AI tools to generate the sequential version of the program from which the basic structure of the parallel encryption algorithm is formed.

Key aspects of this project include:
- Applying AES encryption to a public image dataset
- Demonstrating the complexity of image encryption
- Utilizes AI tools for generating the sequential program version
- Applies parallelism to the encryption algorithm to demonstrates the difference in performance between parallel and sequential encryption.



## Features

- Encrypts and decrypts JPEG and PNG image formats
- Uses AES-256 encryption standard
- Provides console-based interface
- Includes sample encrypted and decrypted images for demonstration


## Usage

To run the application:

1. Clone the repository:
git clone https://github.com/DominoJP/Image-Encryption-AES.git

2. Navigate to the project directory:
cd Image-Encryption-AES

3. Build the solution:

4. Run the application:


## Code Structure

- **/Image-Encryption-Using-AES**
  - `.gitattributes` - Configuration for Git attributes
  - `.gitignore` - Specifies files and directories to ignore in version control
  - `Image Encryption AES.sln` - Visual Studio solution file (Project built in VS 2022)
  - `README.md` - Project documentation
  - `big-mandelbrot.PNG` - Sample image file used for encryption testing (large filesize)
  - `madnelbrot.JPG` - Sample image file used for encryption testing (small filesize)
  - `test.txt` - Test file for verifying encryption and decryption on plaintext
  - **/Image Encryption AES** - Contains main project files and source code
    - `AESFunctions.cpp` - Core AES encryption and decryption functions
    - `AESFunctions.h` - Header file for AES functions
    - `AESProject.cpp` - Main program file for encryption/decryption process
    - `AESmake.mak` - Makefile for compiling the project
    - `BashScript.tar.gz` - Compressed bash scripts for automation
    - `Image Encryption AES.vcxproj` - Visual Studio project file
    - `Image Encryption AES.vcxproj.filters` - Visual Studio project filters
    - **BashScript/** - Directory with additional bash scripts for automation
      - `aes.sh` - bashscript for running the project (still needs decryption instructions)




### Detailed File Explanations

#### AESFunctions.cpp
The **AESFunctions.cpp** file implements the core functionality of the project for both encryption and decryption while handling sequential and parallel processing methods.
 This file contains functions for reading files, encryption, decryption,  expanding the encryption key, and applying AES transformations.

##### Key Components and Functions

1. **File Encryption Functions**:
   - **`encryptFileAES_seq`**: 
     - **Purpose**: Encrypts an entire file sequentially using the AES algorithm.
     - **How It Works**: This function reads data from an input file in chunks, encrypts each chunk block-by-block, and writes the encrypted data to an output file.
     - **Steps**:
       1. **Key Expansion**: Calls the `expandKey` function to generate round keys for AES encryption.
       2. **Block Encryption**: For each chunk, it encrypts each 16-byte block by calling the `encryptBlockAES` function. 
       3. **Padding**: Adds PKCS7 padding to the last block if it’s not a multiple of 16 bytes, ensuring the data length is compatible with AES requirements.
       4. **Performance Measurement**: Measures the time taken for encryption to evaluate performance.

   - **`encryptFileAES_parallel`**: 
     - **Purpose**: Encrypts a file in parallel, leveraging multi-core processing with OpenMP for faster encryption.
     - **How It Works**: This function reads data from an input file in chunks and encrypts block-by-block in a similar way to `encryptFileAES_seq`. 
                         Instead of doing so sequentially it uses OpenMP to parallelize the encryption of multiple blocks within each chunk.
     - **Benefits**: Provides superior speed when compared to sequential implementation on multi-core systems. This is especially true for large files.

2. **File Decryption Functions**:
   - **`decryptFileAES_seq`**:
     - **Purpose**: Decrypts an entire AES-encrypted file sequentially.
     - **How It Works**: This function reads encrypted data from an input file in chunks, decrypts each chunk block-by-block, and writes the decrypted data to an output file.
     - **Steps**:
       1. **Key Expansion**: Calls the `expandKey` function to generate round keys required for AES decryption.
       2. **Block Decryption**: For each chunk, it decrypts each 16-byte block by calling the `decryptBlockAES` function.
       3. **Padding Removal**: Checks for PKCS7 padding on the last block and removes it to decrypt the file.
       4. **Performance Measurement**: Measures the time taken for decryption to assess performance.

   - **`decryptFileAES_parallel`**:
     - **Purpose**: Decrypts a file in parallel using OpenMP, allowing for multi-threaded processing.
     - **How It Works**: This function reads encrypted data from an input file in chunks and decrypts each block in a similar manner to `decryptFileAES_seq`.
                         However, it uses OpenMP to parallelize the decryption of multiple blocks within each chunk.
     - **Benefits**: Significantly faster than the sequential implementation on systems with multiple cores, making it especially efficient for large files.

3. **Block Encryption and Decryption**:
   - **`encryptBlockAES`**:
     - **Purpose**: Encrypts a single 16-byte block using AES transformations.
     - **Steps**:
       1. **Initial Round**: XORs the block with the first round key.
       2. **Rounds**: For each round, it applies the four primary AES transformations: `SubBytes`, `ShiftRows`, `MixColumns`, and `AddRoundKey`.
       3. **Final Round**: Applies `SubBytes`, `ShiftRows`, and `AddRoundKey` without performing `MixColumns`.
     

   - **`decryptBlockAES`**:
     - **Purpose**: Decrypts a single 16-byte block by inversing the AES transformations.
     - **Steps**:
       1. **Initial Round**: XORs the block with the last round key.
       2. **Rounds**: For each round, it applies the four primary inverse AES transformations: `InverseShiftRows`, `InverseSubBytes`, `InverseMixColumns`, and `AddRoundKey`.
       3. **Final Round**: Applies `InverseShiftRows`, `InverseSubBytes`, and `AddRoundKey` without performing `InverseMixColumns`.
     



## Contributing

This project was developed by: Warren Kaye, Andrew Miner, Joshua Planovsky, Daniel Sarmiento , Jhermayne Abdon,  and Ali Maamoun. 
