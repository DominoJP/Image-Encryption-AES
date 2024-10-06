// AESProject.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
// TODO: Allow for 192/256-bit keys

#include <iostream>
#include "AESFunctions.h"

#define KEY_SIZE 128
#define KEY_CHAR_SIZE KEY_SIZE / (sizeof(unsigned char) * 8)
#define KEY_WORD_SIZE KEY_SIZE / (sizeof(uint32_t) * 8)
#define BUFFER_SIZE AES_BLOCK_SIZE


// Encrypted File Extension
const std::string EXT_STR = ".enc";

// Function Declarations
bool testKnown();

int main(int argc, char* argv[])
{
    // Check number of args
    if (argc != 3) {
        std::cout << "Error: incorrect number of arguments! Found " << argc << "." << std::endl;
        return 1;
    }

    // Check Key Length
    int argKeyLength = strlen(argv[2]);
    if (argKeyLength > KEY_CHAR_SIZE) {
        std::cout << "Error: key length to large! Key must be " << KEY_SIZE << "!" << std::endl;
        return 1;
    }

    // Open Input File argv[1]
    std::ifstream fin(argv[1], std::ifstream::binary);
    if (!fin.is_open()) {
        std::cout << "Error: could not open file \"" << argv[1] << "\" for read." << std::endl;
        return 1;
    }

    // Output file name: argv[1] + EXT_STR
    std::string encFile = argv[1] + EXT_STR;

    // Create output file
    std::ofstream fout(encFile, std::ofstream::binary | std::ofstream::out | std::ofstream::trunc);
    if (!fout.is_open()) {
        std::cout << "Error: could not open file \"" << encFile << "\" for write." << std::endl;
        return 1;
    }

    // Print File Info
    std::cout << "Read File: " << argv[1] << std::endl;

    std::cout << "Write File: " << encFile << std::endl;

    fin.seekg(0, fin.end);
    int length = fin.tellg();
    fin.seekg(0, fin.beg);
    std::cout << "\nFile Length: \t" << length << " bytes\n";


    // ==========================================================
    // =               ***   IMPORTANT PART   ***               =
    // ==========================================================
    
    // 128-Bit Key
    unsigned char KEY[KEY_CHAR_SIZE] = {
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };

    // Copy key (will be padded with 0 if < 128-Bits)
    for (int i = 0; i < argKeyLength; ++i)
        KEY[i] = argv[2][i];

    // Debug Print
    std::cout << "\nKey:\t";
    aes::print2DBuffer(KEY, KEY_CHAR_SIZE, 16);
    std::cout << std::endl;

    // Encrypt fin data and write it to fout
    uint32_t* KEY_WORDS = reinterpret_cast<uint32_t*>(KEY);
    aes::encryptFileAES(fin, fout, KEY_WORDS, KEY_WORD_SIZE);

    // ==========================================================
    // =                                                        =
    // ==========================================================

    // Done and close.
    fin.close();
    fout.close();

    // Run Encrpytion Test 
    //testKnown(); // TODO: remove

    return 0;
}

bool testKnown()
{
    static const unsigned char KNOWN_KEY[KEY_CHAR_SIZE] = {
        0x54, 0x68, 0x61, 0x74,
        0x73, 0x20, 0x6D, 0x79,
        0x20, 0x4B, 0x75, 0x6E,
        0x67, 0x20, 0x46, 0x75
    };

    const int KNOWN_KEY_WORDS_SIZE = KEY_SIZE / (sizeof(uint32_t) * 8);
    const uint32_t* KNOWN_KEY_WORDS = reinterpret_cast<const uint32_t*>(KNOWN_KEY);

    static const unsigned char EXPECTED_ENCRYPTION[KEY_CHAR_SIZE] = {
        0x29, 0xC3, 0x50, 0x5F,
        0x57, 0x14, 0x20, 0xF6,
        0x40, 0x22, 0x99, 0xB3,
        0x1A, 0x02, 0xD7, 0x3A
    };

    std::vector<unsigned char> dataBuffer = {
        0x54, 0x77, 0x6F, 0x20,
        0x4F, 0x6E, 0x65, 0x20,
        0x4E, 0x69, 0x6E, 0x65,
        0x20, 0x54, 0x77, 0x6F
    };

    uint32_t roundWords[11 * 4] = { 0 };
    aes::expandKeys(roundWords, 10, KNOWN_KEY_WORDS, KNOWN_KEY_WORDS_SIZE);

    std::cout << "\nKey: \n";
    aes::print2DBuffer(KNOWN_KEY, KEY_CHAR_SIZE, 16);

    std::cout << "\nOriginal Data: \n";
    aes::print2DBuffer(dataBuffer.data(), dataBuffer.size(), 16);

    std::cout << "\nExpected Encryption: \n";
    aes::print2DBuffer(EXPECTED_ENCRYPTION, KEY_CHAR_SIZE, 16);

    aes::encryptBlockAES(dataBuffer, roundWords, 10, KNOWN_KEY_WORDS, KNOWN_KEY_WORDS_SIZE);

    std::cout << "\nEncrypted Data: \n";
    aes::print2DBuffer(dataBuffer.data(), dataBuffer.size(), 16);
    
    bool matched = true;
    for (int i = 0; i < KEY_CHAR_SIZE; ++i) {
        if (dataBuffer[i] != EXPECTED_ENCRYPTION[i]) {
            matched = false;
            break;
        }
    }
    std::cout << "\nExpected Encryption and Actual Encryption Match: " << (matched ? "true" : "false") << std::endl;

    return matched;
}