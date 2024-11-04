// AESProject.cpp : This file contains the 'main' function. Program execution begins and ends there.


#include <iostream>
#include <array>
#include "AESFunctions.h"
#include <cstring>

#define BUFFER_SIZE AES_BLOCK_SIZE


// Encrypted File Extension
const std::string EXT_STR_seq = "_seq.enc";
const std::string EXT_STR_par = "_par.enc";

// Function Declarations
/**
 * @brief To test AES 128-bit encryption with a known key
 * 
 * @return Test passes if true, else false
 */
bool testKnown128();

//Timings
double sequential_time_total;
double parallel_time_total;



// Prints the CLI usage text to the terminal.

static void printHelpMsg(void)
{
    const char* help_msg = R"heredoc(
    Usage:
        $ & 'Image Encryption AES.exe' <inputFile> <key> [-spde]

    Arguments:
        inputFile:  path to file that needs encrypting.  Output file will be
                    named <inputFile>_(seq|par).enc
        key:        a string of characters, enabling different encryption
                    modes:
                      1 - 16 chars:  AES 128-bit mode.
                      17 - 24 chars: AES 192-bit mode.
                      25 - 32 chars: AES 256-bit mode.
    Optional flags:
        -s          Run in sequential mode only.
        -p          Run in parallel mode only.
        -d          Run decryption instead of encryption for the specified
                    mode(s).
        -e          Run encryption for the specified modes, as opposed to
                    decryption (default).
        (no flag)   Run encryption for both modes and compare outputs.
    )heredoc";

    std::cout << help_msg << std::endl;
}


/****************************************************************
* MAIN FUNCTION
* 
* The function will encrypt or decrypt input files 
* through using the AES algorithm sequentially or parallelized 
* depending on the command line arguments that are given.
* 
* @param argc Number of command line arguments
* @param argv Array of command line arguments
* 
* @return int Return 1 on error
*****************************************************************/
int main(int argc, char* argv[])
{
    /*** CONFIG VARIABLES ***/
    bool optionSequential = true; /**< Flag for sequential mode */
    bool optionParallel = true; /**< Flag for parallel mode */
    bool optionDecrypt = false; /**< Flag for decryption mode */

    /*** VALIDATE ARGUMENTS ***/
    // Minor improvements maintain backward compatibility with major version number.
    // Increment version number when breaking backward compatibility.
    // 
    // CLI v0.0:
    // First argument is a filename
    // Second argument is a key
    // 
    // CLI v0.1:
    // First argument is a filename
    // Second argumetn is a key
    // Optional 3rd argument stars with a '-' and contains flags which have no arguments:
    // -s run in series only, or
    // -p run in parallel only
    // (default): run both series and parallel
    // 
    // CLI v0.2
    // 3rd argument may now include 'd' for decrypt
    // e.g. -ds or -sd would run a sequential-only decryption
    // 
    // TODO: Future ideas:
    // -q quiet mode
    // -t measure time
    // (default) verbose mode, time not measured

    // Check number of args
    if ((argc < 3) || (argc > 4)) {
        printHelpMsg();
        return 1;
    }

    // Check Key Length
    size_t argKeyLength = strlen(argv[2]);
    if (argKeyLength > KEY_SIZE_BYTES_256) {
        std::cout << "Error: key length too large! Key must be ";
        std::cout << KEY_SIZE_BYTES_256 << " characters or less!" << std::endl;
        return 1;
    }

    // Check for additional options
    if( argc > 3 )
    {
        // TODO: add loop to find options in other locations.  For now we're just naively checking at argv[3]
        if( (strlen(argv[3]) < 2) || ('-' != argv[3][0]) )
        {
            printHelpMsg();
            return 1;
        }

        const std::size_t arglen = strlen(argv[3]);

        for (unsigned int i = 1; i < arglen; i++)
        {
            switch (argv[3][i])
            {
            case 's':
                optionSequential = true;
                optionParallel = false;
                break;
            case 'p':
                optionParallel = true;
                optionSequential = false;
                break;
            case 'd':
                optionDecrypt = true;
                break;
            case 'e':
                optionDecrypt = false;
                break;
            default:
                printHelpMsg();
                break;
            }
        }
    }

    /**
     * @brief Output selected run mode and encryption and decryption options.
     * 
     * Displays what mode the program is run in, sequential or parallel and will perform
     * encryption or decrpytion based on the command line options that were provided
     */
    std::cout << "Run Mode:" << std::endl;
    std::cout << "  Do Sequential:   " << ((optionSequential) ? "TRUE" : "FALSE") << std::endl;
    std::cout << "  Do Parallel:     " << ((optionParallel) ? "TRUE" : "FALSE") << std::endl;
    std::cout << "  Encryption mode: " << ((optionDecrypt) ? "DECRYPT" : "ENCRYPT") << std::endl;

    // Open Input File argv[1]
    std::ifstream fin(argv[1], std::ifstream::binary);
    if (!fin.is_open()) {
        std::cout << "Error: could not open file \"" << argv[1] << "\" for read." << std::endl;
        return 1;
    }
    std::cout << "Read File: " << argv[1] << std::endl;

    /**
    * @brief Calculate size of input file in bytes
    * 
    * This will move the file pointer to the end of the file and 
    * then read position and return file pointer to beginning
    * 
    * @param fin Input file stream
    * 
    * @return Size of the file in bytes
    */
    fin.seekg(0, fin.end);
    const std::streamoff length = fin.tellg();
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

    /** 
     * @brief Copy key into key buffer
     * 
     * This loop will fill key with the values from argv[2] and
     * if key is shorter than 256 bits it is automatically 
     * padded with zeros
     * 
     * @param argv[2] The key provided by user
     */
    for (size_t i = 0; i < argKeyLength; ++i)
    {
        key[i] = static_cast<unsigned char>(argv[2][i]);
    }

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
    aes::printBufferRowMajorOrder(key, keyWordSize * 4, keyWordSize * 4); // keyWordSize * 4 = KEY_SIZE_BYTES
    std::cout << std::endl;

    // Encrypt fin data and write it to fout
    uint32_t* keyWords = reinterpret_cast<uint32_t*>(key);

    // Declare output files
    std::string encFile_seq = "";
    std::string encFile_par = "";

    /**
     * @brief Run sequential encryption
     * 
     * Opens output file and will write encryption data sequentially
     * It will display errors and exit if output file can't be opened
     * 
     * @return int Returns 1 if the output file cannot be opened, 0 for success
     */
    if( optionSequential )
    {
        // Prepare output
        encFile_seq = argv[1] + EXT_STR_seq;  // TODO: different filename for decrypt
        std::ofstream fout_seq(encFile_seq, std::ofstream::binary | std::ofstream::out | std::ofstream::trunc);

        if (!fout_seq.is_open()) {
            std::cout << "Error: could not open file \"" << encFile_seq << "\" for write." << std::endl;
            return 1;
        }
        std::cout << "Sequential Write File: " << encFile_seq << std::endl;

        // Senquentially encrypt or decrypt
        if (!optionDecrypt)
        {
            sequential_time_total = aes::encryptFileAES_seq(fin, fout_seq, keyWords, keyWordSize);
        }
        else
        {
            sequential_time_total = aes::decryptFileAES_seq(fin, fout_seq, keyWords, keyWordSize);  // TODO: add arguments
        }

        std::cout << "Sequential time: " << sequential_time_total << std::endl;

        fout_seq.close();

        // Reset the input file stream to beginning
        fin.clear();
        fin.seekg(0, std::ios::beg);
    }

    /** 
     * @brief Run parallel encryption
     * 
     * Opens output file and will write encryption data parallelized
     * It will display errors and exit if output file can't be opened
     * 
     * @return int Returns 1 if the output file cannot be opened, 0 for success
     */
    if (optionParallel)
    {
        // Prepare output
        encFile_par = argv[1] + EXT_STR_par;  // TODO: different filename for decrypt
        std::ofstream fout_par(encFile_par, std::ofstream::binary | std::ofstream::out | std::ofstream::trunc);

        if (!fout_par.is_open()) {
            std::cout << "Error: could not open file \"" << encFile_par << "\" for write." << std::endl;
            return 1;
        }
        std::cout << "Parallel Write File: " << encFile_par << std::endl;

        // Parallelized encrypt or decrypt
        if (!optionDecrypt)
        {
            parallel_time_total = aes::encryptFileAES_parallel(fin, fout_par, keyWords, keyWordSize);
        }
        else
        {
            parallel_time_total = aes::decryptFileAES_parallel();  // TODO: add arguments
        }

        std::cout << "Parallel time: " << parallel_time_total << std::endl;

        fout_par.close();
    }
    /*** End data encryption section ***/

    // Done with input file.
    fin.close();

    if( optionSequential && optionParallel )
    {
        std::cout << "Do Output Files Match: " << aes::compareFiles(encFile_seq, encFile_par) << std::endl;;
    }

    // Run Encrpytion Test 
    //testKnown(); // TODO: remove

    return 0;
}

/**
 * @brief Test function to check if 128-bit encryption 
 * is working with a known key and plaintext
 * 
 * @return True if encryption test is successful, else false
 */
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

    // 128-bits of example data - this is altered by the AES algorithm
    std::array<unsigned char, KEY_SIZE_BYTES_128> dataBuffer = {
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

    /**
     * Generate keys for each round for AES encryption
     * 
     * Expand initial key into round keys for
     * each round of AES
     * 
     * @param roundWords Buffer to store expanded round keys
     * @param rounds Number of rounds
     * @param KNOWN_KEY_WORDS Pointer to initial key words
     * @param KEY_SIZE_WORDS_128 Size of key in words
     */
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


    /**
     * @brief AES Encryption
     * 
     * Encrypt data buffer with 10 rounds using 128-bit key
     * 
     * @param dataBuffer Data to be encrypted
     * @param roundWords Array with expanded round keys
     * @param rounds Number of rounds
     * @param KNOWN_KEY_WORDS Pointer to 128-bit key
     * @param KEY_SIZE_WORDS_128 Size of key in words
     */
    aes::encryptBlockAES(dataBuffer.data(), roundWords, 10, KNOWN_KEY_WORDS, KEY_SIZE_WORDS_128);

    // Print dataBuffer after it's encrypted
    std::cout << "\nEncrypted Data: \n";
    aes::printBufferRowMajorOrder(dataBuffer.data(), dataBuffer.size(), 16);

    // Check if encrypted dataBuffer and expected encryption data match
    bool matched = true;
    unsigned char data = 0;
    unsigned char expected = 0;

    for (unsigned int i = 0; i < KEY_SIZE_BYTES_128; i++) {
        data = dataBuffer[i];  // TODO: Avoid Spectre mitigation (Warning C5045)
        expected = EXPECTED_ENCRYPTION[i];
        if( data != expected )
        {
            matched = false;
            break;
        }
    }

    // Print match results
    std::cout << "\nExpected Encryption and Actual Encryption Match: " << (matched ? "true" : "false") << std::endl;

    return matched;
}