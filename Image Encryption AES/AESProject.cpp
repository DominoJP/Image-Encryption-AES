// AESProject.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
// TODO: Allow for 192/256-bit keys

#include <iostream>
#include "AESFunctions.h"

#define BUFFER_SIZE AES_BLOCK_SIZE


// Encrypted File Extension
const std::string EXT_STR_seq = "_seq.enc";
const std::string EXT_STR_par = "_par.enc";

// Function Declarations
bool testKnown128();


/****************
* Main function
* 
* Expects two additional arguments:
* _ 
* _ 
*****************/
int main(int argc, char* argv[])
{
    /*** VALIDATE ARGUMENTS ***/
    // Check number of args
    if (argc != 3) {
        std::cout << "Error: incorrect number of arguments! Found " << argc << "." << std::endl;
        return 1;
    }

    // Check Key Length
    size_t argKeyLength = strlen(argv[2]);
    if (argKeyLength > KEY_SIZE_BYTES_256) {
        std::cout << "Error: key length to large! Key must be ";
        std::cout << KEY_SIZE_BITS_256 << "-bits or less!" << std::endl;
        return 1;
    }

    // Open Input File argv[1]
    std::ifstream fin(argv[1], std::ifstream::binary);
    if (!fin.is_open()) {
        std::cout << "Error: could not open file \"" << argv[1] << "\" for read." << std::endl;
        return 1;
    }

    /*** PREPARE OUTPUT ***/
    // Output file name: argv[1] + EXT_STR
    std::string encFile_seq = argv[1] + EXT_STR_seq;
    std::string encFile_par = argv[1] + EXT_STR_par;

    // Create sequential output file
    std::ofstream fout_seq(encFile_seq, std::ofstream::binary | std::ofstream::out | std::ofstream::trunc);
    if (!fout_seq.is_open()) {
        std::cout << "Error: could not open file \"" << encFile_seq << "\" for write." << std::endl;
        return 1;
    }

    std::ofstream fout_par(encFile_par, std::ofstream::binary | std::ofstream::out | std::ofstream::trunc);
    if (!fout_par.is_open()) {
        std::cout << "Error: could not open file \"" << encFile_par << "\" for write." << std::endl;
        return 1;
    }

    // Print File Info
    std::cout << "Read File: " << argv[1] << std::endl;

    std::cout << "Sequential Write File: " << encFile_seq << std::endl;
    std::cout << "Parallel Write File: " << encFile_par << std::endl;

    fin.seekg(0, fin.end);
    std::streamoff length = fin.tellg();
    fin.seekg(0, fin.beg);
    std::cout << "\nFile Length: \t" << length << " bytes\n";

    /*** DATA ENCRYPTION SECTION ***/
    
    // 256-Bit Key Buffer
    unsigned char key[KEY_SIZE_BYTES_256] = {
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };

    // Copy key (will automatically be padded with 0 if < 256-bits)
    for (int i = 0; i < argKeyLength; ++i)
        key[i] = argv[2][i];


    // TODO: Add 3rd parameter to specify key size
    // Size of key in words: KEY_SIZE_BYTES / 32
    std::size_t keyWordSize = KEY_SIZE_WORDS_128;
    if (argKeyLength > KEY_SIZE_BYTES_128) {
        if (argKeyLength > KEY_SIZE_BYTES_192)
            keyWordSize = KEY_SIZE_WORDS_256;
        else
            keyWordSize = KEY_SIZE_WORDS_192;
    }

    // Print key info
    std::cout << "\nKey Size (Bits): \t" << keyWordSize * 32 << std::endl;
    std::cout << "Key Size (Words): \t" << keyWordSize << std::endl;

    std::cout << "\nKey:\n";
    aes::printBufferRowMajorOrder(key, keyWordSize * 4, 16); // keyWordSize * 4 = KEY_SIZE_BYTES
    std::cout << std::endl;

    // Encrypt fin data and write it to fout
    uint32_t* keyWords = reinterpret_cast<uint32_t*>(key);

    // Run sequential encryption
    aes::encryptFileAES_seq(fin, fout_seq, keyWords, keyWordSize);
    
    //reset the input file stream
    fin.clear();
    fin.seekg(0, std::ios::beg);

    // Run parallel encryption
    aes::encryptFileAES_parallel(fin, fout_par, keyWords, keyWordSize);

    /*** End data encryption section ***/

    // Done and close.
    fin.close();
    fout_seq.close();
    fout_par.close();

    std::cout << "Do Output Files Match: " << aes::compareFiles(encFile_seq, encFile_par) << std::endl;;

    // Run Encrpytion Test 
    //testKnown(); // TODO: remove

    return 0;
}


// Test function to check if 
// 128-bit encryption is working
bool testKnown128()
{
    // 128-bit example key
    static const unsigned char KNOWN_KEY[KEY_SIZE_BYTES_128] = {
        0x54, 0x68, 0x61, 0x74,
        0x73, 0x20, 0x6D, 0x79,
        0x20, 0x4B, 0x75, 0x6E,
        0x67, 0x20, 0x46, 0x75
    };

    // Expected data after encrypting dataBuffer
    static const unsigned char EXPECTED_ENCRYPTION[KEY_SIZE_BYTES_128] = {
        0x29, 0xC3, 0x50, 0x5F,
        0x57, 0x14, 0x20, 0xF6,
        0x40, 0x22, 0x99, 0xB3,
        0x1A, 0x02, 0xD7, 0x3A
    };

    // 128-bits of example data
    std::vector<unsigned char> dataBuffer = {
        0x54, 0x77, 0x6F, 0x20,
        0x4F, 0x6E, 0x65, 0x20,
        0x4E, 0x69, 0x6E, 0x65,
        0x20, 0x54, 0x77, 0x6F
    };

    // Cast KNOWN_KEY into array of 32-bit elements
    const uint32_t* KNOWN_KEY_WORDS = reinterpret_cast<const uint32_t*>(KNOWN_KEY);

    // Allocate buffer for round keys
    // Number of 32-bit key words after expansion
    // equals 4 * (Nr + 1) according to FIPS 197
    uint32_t roundWords[11 * 4] = { 0 };

    // Generate keys for each round
    aes::expandKey(roundWords, 10, KNOWN_KEY_WORDS, KEY_SIZE_WORDS_128);

    // Print Key
    std::cout << "\nKey: \n";
    aes::printBufferRowMajorOrder(KNOWN_KEY, KEY_SIZE_BYTES_128, 16);

    // Print dataBuffer before encryption
    std::cout << "\nOriginal Data: \n";
    aes::printBufferRowMajorOrder(dataBuffer.data(), dataBuffer.size(), 16);

    // Print expected encryption data
    std::cout << "\nExpected Encryption: \n";
    aes::printBufferRowMajorOrder(EXPECTED_ENCRYPTION, KEY_SIZE_BYTES_128, 16);


    // AES Encryption
    // 10 rounds using 128-bit key
    aes::encryptBlockAES(dataBuffer.data(), roundWords, 10, KNOWN_KEY_WORDS, KEY_SIZE_WORDS_128);

    // Print dataBuffer after it's encrypted
    std::cout << "\nEncrypted Data: \n";
    aes::printBufferRowMajorOrder(dataBuffer.data(), dataBuffer.size(), 16);

    // Check if encrypted dataBuffer and expected encryption data match
    bool matched = true;
    for (int i = 0; i < KEY_SIZE_BYTES_128; ++i) {
        if (dataBuffer[i] != EXPECTED_ENCRYPTION[i]) {
            matched = false;
            break;
        }
    }

    // Print match results
    std::cout << "\nExpected Encryption and Actual Encryption Match: " << (matched ? "true" : "false") << std::endl;

    return matched;
}