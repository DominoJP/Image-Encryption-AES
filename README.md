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
6. [A.I. Implementation](#a.i._implementation)


## Introduction

Image Encryption using AES is a C++ program designed to encrypt images using both sequential and parallel versions of the AES encryption algorithm.
This project was designed to apply AES encryption to a public image dataset in order demonstrate the difference between sequential encryption and parallel encryption.
Furthermore, the project utilizes AI tools to generate the sequential version of the program from which the basic structure of the parallel encryption algorithm is formed.
Finally, The parallel version of the program leverages OpenMP, which serves as an extensive library for multi-threaded parallel processing in C++.
Using OpenMP, the program distributes the workload of encrypting image data across multiple CPU cores. This is useful for encrypting large images or datasets since it reduces the time required compared to a purely sequential implementation.



Key aspects of this project include:
- Applying AES encryption to a public image dataset
- Demonstrating the complexity of image encryption
- Utilizes AI tools for generating the sequential program version
- Applies parallelism to the encryption algorithm to demonstrate the difference in performance between parallel and sequential encryption.



## Features

- Encrypts and decrypts JPEG and PNG image formats
- Uses AES-256 encryption standard
- Provides console-based interface
- Includes sample encrypted and decrypted images for demonstration
- Utilizes OpenMP to achieve parallel processing


## Usage

To run the application:

1. Clone the repository:
git clone https://github.com/DominoJP/Image-Encryption-AES.git

2. Navigate to the project directory on your system either via command line or file explorer:
cd Image-Encryption-AES

3. Build and Run the project

**To build and run the project with Visual Studio**
  1. **Open the Project in Visual Studio**:
     - Open Visual Studio.
     - Select **Open a project or solution** and navigate to the `.sln` file in your project directory (`Image Encryption AES.sln`).
     - Or simply double-click the vcxproj file in your project directory.

2. **Configure OpenMP (for parallel processing)**:
   - Go to **Project** > **Properties**.
   - Under **Configuration Properties** > **C/C++** > **Language**, set **OpenMP Support** to **Yes**. This will enable OpenMP for parallel processing configurations

3. **Set the Build Configuration**:
   - Ensure that the configuration is set to **Debug** 
   - Select **Build** > **Build Solution** to compile the project.

4. **Run the Application**:
   - After building, you should see the executable in the project's `Debug` folder.
   - You can run the executable with the necessary arguments directly from Visual Studio (under **Debug** > **Start Without Debugging**).


**To build and run the project via command line**

  1. **Build the solution:** 
     - Use the following command to build the executable with openmp support.
     - `g++ *.cpp -fopenmp -o AES_Encryption`


  2. **Run the application:**
     - Once the executable file is created, you can run the program using the following command.
     -`./AES_Encryption <inputFile> <key> [-spde]`
        -`<image_file_path>`: Path to the image file you want to encrypt or decrypt.
        - `<key>`: A string of characters for encryption, which determines the key size:
          - 16 characters: AES 128-bit mode.
          - 17–24 characters: AES 192-bit mode.
          - 25–32 characters: AES 256-bit mode.
        - `<flag>`: Specifies the operation mode:
        - `-s` for sequential mode only.
        - `-p` for parallel mode only.
        - `-e` for encryption flag. 
        - `-d` for decryption flag. 

**To build and run the project via bashscript**

**for CSUN VM:**
  - `aem22021@10.166.250.31:/home/aem22021/dev/comp535/project1`


  1. **Run the Bash script to display usage information:**
     - run the following command to display usage info.
      -`./aes.sh -h`
    
  2. **The usage help for the Bash script will display options for running the program:**
     - `./aes.sh [-d input_images_directory] [-e executable_path] [-s (sequential)] [-p (parallel)] [-k (128/192/256)] [-x (enable decryption)]`

  3. **Note:**
    - You can simply run ./aes.sh to run the executable and input images in the current directory to run AES-128 ENCRYPTION both sequentially and in parallel.
     Running sequentially plus decrypting may take up to 4 minutes to complete the whole dataset on a VM.
    - Any output from the executable will be piped into ./AES_Encryption_output.txt







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
      - `aes.sh` - bashscript for running the project 




### Detailed File Explanations for Core Files

#### AESFunctions.cpp
The **AESFunctions.cpp** file implements the core functionality of the project for both encryption and decryption while handling sequential and parallel processing methods.
 This file contains functions for reading files, encryption, decryption,  expanding the encryption key, and applying AES transformations.

##### Key Components and Functions

1. **File Encryption Functions**:
   - **`encryptFileAES_seq`**: 
     - **Purpose**: Encrypts an entire file sequentially using the AES algorithm. This function reads data from an input file in chunks, encrypts each chunk block-by-block by calling `encryptBlockAES`, and writes the encrypted data to an output file. 
                    If the last block isn’t a multiple of 16 bytes, it applies PKCS7 padding to ensure AES can be utilized. Additionally, it can measure execution time for performance evaluation.
     - **Steps**:
       1. **Key Expansion**: Calls the `expandKey` function to generate round keys for AES encryption.
       2. **Block Encryption**: For each chunk, it encrypts each 16-byte block by calling the `encryptBlockAES` function. 
       3. **Padding**: Adds PKCS7 padding to the last block if it’s not a multiple of 16 bytes, ensuring the data length is compatible with AES requirements.
       4. **Performance Measurement**: Measures the time taken for encryption to evaluate performance.

   - **`encryptFileAES_parallel`**: 
     - **Purpose**:This function reads data from an input file in chunks and encrypts block-by-block in a similar way to `encryptFileAES_seq`. 
                         Instead of doing so sequentially it uses OpenMP to parallelize the encryption of multiple blocks within each chunk.
     - **Benefits**: Provides superior speed when compared to sequential implementation on multi-core systems. This is especially true for large files.

2. **File Decryption Functions**:
   - **`decryptFileAES_seq`**:
     - **Purpose**: Decrypts an entire AES-encrypted file sequentially by reading encrypted data from an input file in chunks, decrypting each chunk block-by-block, and writing the decrypted data to an output file.
       1. **Key Expansion**: Calls the `expandKey` function to generate round keys required for AES decryption.
       2. **Block Decryption**: For each chunk, it decrypts each 16-byte block by calling the `decryptBlockAES` function.
       3. **Padding Removal**: Checks for PKCS7 padding on the last block and removes it to decrypt the file.
       4. **Performance Measurement**: Measures the time taken for decryption to assess performance.

   - **`decryptFileAES_parallel`**:
     - **Purpose**: This function reads encrypted data from an input file in chunks and decrypts each block in a similar manner to `decryptFileAES_seq`.
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

4. **Key Expansion**:
   - **`expandKey`**:
     - **Purpose**: This function generates the round keys from the AES key, as specified by the AES standard (FIPS 197).

5. **Helper Functions**:
   - **Padding Function**:
     - **`padPKCS7`**:
       - **Purpose**: Adds PKCS7 padding to the data, ensuring that the length of the data for the block is a multiple of 16.

     - **`getSizeBeforePKCS7Padding`**:
       - **Purpose**: Removes PKCS7 padding after decryption to restore the original data size.
- **Transformation Functions**:
     - **`rotateWordLeft`**:
       - **Purpose**: Rotates a 32-bit word left by a specified number of bytes, assisting in key expansion..

     - **`sBoxSubstitution`**:
       - **Purpose**: Substitutes each byte with a value from the AES S-Box.

     - **`inverseSBoxSubstitution`**:
       - **Purpose**: Reverses `sBoxSubstitution` during decryption using values from the inverse AES S-Box.

     - **`mixColumns`**:
       - **Purpose**: Transforms the data by combining bytes within each column to spread out bits

     - **`inverseMixColumns`**:
       - **Purpose**: Reverses the `mixColumns` transformation, reconstructing original column data for decryption.


### AESFunctions.handles
**AESFunctions.h** serves as a header file for our implementation of AES encryption and decryption functions. It defines constants, function declarations, and AES parameters. 
This file provides the essential declarations and configurations needed by the functions located in `AESFunctions.cpp`.


### AESProject.cpp

**AESProject.cpp** serves as the main entry point of the program, managing user input, configuring encryption and decryption settings, and invoking core AES functions. 
It handles both sequential and parallel encryption or decryption, based on user-provided command-line arguments.

#### Key Components and Functions

1. **Command-Line Interface (CLI): `printHelpMsg`**:
   - **Purpose**: Prints help msg that indicates the program accepts user command-line arguments to run encryption/decryption options, key size, and input file.
   - **Options**:
     - `-s`: Sequential mode only
     - `-p`: Parallel mode only
     - `-d`: Decryption (for specified modes)
     - `-e`: Encryption mode (for specified modes; serves as default selection)
     - `no flag`: Run encryption for both modes and compare outputs.

2. **Main Function**:
   - **Purpose**: Initializes the command line configuration, validates inputs, and executes program per the selected options.
   - **Steps**:
     1. **Configuration Setup**: Sets default values for configuration options (`optionSequential`, `optionParallel`, `optionDecrypt`) and reads additional options from command-line arguments.
                                 It then takes the key from user input and adjusts key size based on the length (128, 192, or 256 bits). If the key is shorter than the specified size it will add padding.
     2. **Encryption and Decryption Execution**: Based on the user CLI arguments::
        - Opens the input file for reading.
        - Sets up output files for encrypted data, with extensions indicating sequential (`_seq.enc`) or parallel (`_par.enc`) mode.
        - Runs sequential or parallel encryption/decryption by calling `encryptFileAES_seq` or `decryptFileAES_seq` and `encryptFileAES_parallel` or `decryptFileAES_parallel`.

3. **Sequential and Parallel Processing**:
   - **Sequential Mode**: Runs encryption or decryption sequentially by calling either `encryptFileAES_seq` or `decryptFileAES_seq` on the input file.
   - **Parallel Mode**: Runs in parallel using OpenMP, calling `encryptFileAES_parallel` or `decryptFileAES_parallel`, distributing tasks across multiple cores for faster processing.

4. **File Comparison and Verification**:
   - **Purpose**: Calls `aes::compareFiles` to perform a byte-by-byte comparison of the sequential and parallel output files.


## Contributing

This project was developed by: Warren Kaye, Andrew Miner, Joshua Planovsky, Daniel Sarmiento , Jhermayne Abdon,  and Ali Maamoun. 

## A.I. Implementation and Outside Code Sources

Due to the complex nature of this project this group was allowed to use generative A.I. to create sequential implementation of the program. Primarily, we used ChatGPT
to create a sequential encryption implementation and expanded from there in order to develop our parralel and decryption functions. The link to the prompts given to ChatGPT
can be found here:  https://chatgpt.com/share/6701af5b-db5c-8006-86dc-3a844d136514
(Note: Using ctrl+f "note" in the source code will list every function ChatGPT helped with)

Secondly in order to implement our bashscript we also utilized chatgpt to help us formulate the logic  for it using the following prompts:
[Previous Bash Script]
1. make this bash script have the option to take arguments for a directory of input images 
2. take a flag -p or -s to only run all files in parallel or sequential by adding the flag -s or -p to the executable command 
3. also add an option for an executable path and create a usage flag which will only display help information for how to use the script
4. also make a flag for which key type to use make the default 128. add to help usage
5. i have made some changes, now include the usage of decryption! by adding -x, we will do all we have done by default, both sequential and parallel and then decrypt in sequential and parallel, but if the user puts -x and -p, then we will encrypt in parallel then decrypt in parallel. also add this to the usage.
Generated using OpenAI. https://chat.openai.com/” 
(Note: we were unable to generate a full chat link due to limitations on illustrations)


Finally, in order to ensure that our files were identical we made use of a compareFiles function found on stack overflow which can be cited here:
https://stackoverflow.com/questions/6163611/compare-two-files
