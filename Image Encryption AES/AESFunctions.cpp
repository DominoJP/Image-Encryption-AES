#include "AESFunctions.h"

#include <omp.h>

#include <iostream>
#include <bitset>
#include <cassert>

/**
 * @brief Encrypt file sequentially using AES encryption
 * 
 * This function will read data from input file and us AES encrypt block-by-block
 * It will write encrypted data to output file
 * 
 * @param inFile Input file stream
 * @param outFile Output file stream
 * @param key Pointer to AES key
 * @param keyWordSize Key size in words
 * 
 * @return Total time it takes for encryption to take
 */
double aes::encryptFileAES_seq(std::ifstream& inFile, std::ofstream& outFile, uint32_t* key, std::size_t keyWordSize)
{
    static constexpr int CHUNK_SIZE = AES_BLOCK_SIZE * 2000;

    assert(inFile.is_open());
    assert(outFile.is_open());

    // Number of rounds, based on key size
    std::size_t numRounds = getNumbRounds(keyWordSize);

    // Allocate buffer for round keys
    // Number of 32-bit key words after expansion
    // equals 4 * (Nr + 1) according to FIPS 197
    std::vector<uint32_t> expandedKey = std::vector<uint32_t>((numRounds + 1) * 4, 0);

    // Generate keys for each round
    expandKey(expandedKey.data(), numRounds, key, keyWordSize);

    // Allocate buffer for reading/writing 128-bit blocks
    std::vector<unsigned char> buffer = std::vector<unsigned char>(CHUNK_SIZE, 0);

    // Size of data read into buffer
    std::streamsize dataSize = 0;

    inFile.seekg(0, inFile.end);
    const std::streamsize fileSize = inFile.tellg();
    inFile.seekg(0, inFile.beg);

    double seq_start_time;
    double seq_end_time;
    double seq_time = 0;
    
    // While there is more data to read
    while (!inFile.eof()) {
        // Read chunk
        inFile.read(reinterpret_cast<char*>(buffer.data()), buffer.size());

        // Get size of chunk read
        dataSize = inFile.gcount();

        // If the last aes block is less than 128-bits pad it.
        if (dataSize % AES_BLOCK_SIZE != 0) {
            const std::streampos endOfLastBlock = dataSize - dataSize % AES_BLOCK_SIZE;
            const unsigned int sizeOfLastBlock = dataSize % AES_BLOCK_SIZE;
            aes::padPKCS7(buffer.data() + endOfLastBlock, AES_BLOCK_SIZE, sizeOfLastBlock);
            dataSize += AES_BLOCK_SIZE - sizeOfLastBlock;

            // Debug Print
            //std::cout << "Padded Last Block: \n";
            //printBufferColMajorOrder(buffer.data() + endOfLastBlock, AES_BLOCK_SIZE, AES_BLOCK_COLS);
        }

        assert(dataSize % AES_BLOCK_SIZE == 0);
        const long long numBlocks = dataSize / AES_BLOCK_SIZE;

        seq_start_time = omp_get_wtime();
        for (int i = 0; i < numBlocks; ++i) {
            encryptBlockAES(buffer.data() + (std::size_t(i) * AES_BLOCK_SIZE), expandedKey.data(), numRounds, key, keyWordSize);
        }
        seq_end_time = omp_get_wtime();
        seq_time += seq_end_time - seq_start_time;

        // Write encrypted data to new file.
        outFile.write(reinterpret_cast<char*>(buffer.data()), dataSize);
    }

    // If the entire file was divisible 
    // by 128-bits then add one extra
    // padded block per PKCS7 standard
    if (fileSize % AES_BLOCK_SIZE == 0) {
        aes::padPKCS7(buffer.data(), AES_BLOCK_SIZE, 0);

        // AES Encryption
        encryptBlockAES(buffer.data(), expandedKey.data(), numRounds, key, keyWordSize);

        // Write encrypted data to new file.
        outFile.write(reinterpret_cast<char*>(buffer.data()), AES_BLOCK_SIZE);
    }

    // Return total time it took to run encrypting sequentially
    return seq_time;
}

/**
 * @brief Encrypt file using AES parallelized
 * 
 * This function will read input file and encrypt a chunk using AES encryption
 * and write encrypted data to output
 * 
 * @param inFile Input file stream
 * @param outFile Output file stream
 * @param key Pointer to AES key
 * @param keyWordSize Key size in words
 */
double aes::encryptFileAES_parallel(std::ifstream& inFile, std::ofstream& outFile, uint32_t* key, std::size_t keyWordSize)
{
    const int CHUNK_SIZE = AES_BLOCK_SIZE * 2000; //finalFileSize;

    assert(inFile.is_open() && outFile.is_open());

    // Number of rounds, based on key size
    std::size_t numRounds = getNumbRounds(keyWordSize);

    // Allocate buffer for round keys
    // Number of 32-bit key words after expansion
    // equals 4 * (Nr + 1) according to FIPS 197
    std::vector<uint32_t> expandedKey = std::vector<uint32_t>((numRounds + 1) * 4, 0);

    // Generate keys for each round
    expandKey(expandedKey.data(), numRounds, key, keyWordSize);

    // Allocate buffer for reading/writing 128-bit blocks
    std::vector<unsigned char> buffer = std::vector<unsigned char>(CHUNK_SIZE, 0);

    // Size of data read into buffer
    std::streamsize dataSize = 0;

    inFile.seekg(0, inFile.end);
    const std::streamsize fileSize = inFile.tellg();
    inFile.seekg(0, inFile.beg);

    double par_start_time;
    double par_end_time;
    double par_time = 0;
    // While there is more data to read
    while (!inFile.eof()) {
        // Read block
        inFile.read(reinterpret_cast<char*>(buffer.data()), buffer.size());

        // Get size of data read
        dataSize = inFile.gcount();

        // If the last block is less than 128-bits pad it.
        if (dataSize % AES_BLOCK_SIZE != 0) {
            const std::streampos endOfLastBlock = dataSize - dataSize % AES_BLOCK_SIZE;
            const unsigned int sizeOfLastBlock = dataSize % AES_BLOCK_SIZE;
            aes::padPKCS7(buffer.data() + endOfLastBlock, AES_BLOCK_SIZE, sizeOfLastBlock);
            dataSize += AES_BLOCK_SIZE - sizeOfLastBlock;

            // Debug Print
            //std::cout << "Padded Last Block: \n";
            //printBufferColMajorOrder(buffer.data() + endOfLastBlock, AES_BLOCK_SIZE, AES_BLOCK_COLS); 
        }

        assert(dataSize % AES_BLOCK_SIZE == 0);

        const long long numBlocks = dataSize / AES_BLOCK_SIZE;
        
        par_start_time = omp_get_wtime();

#       pragma omp parallel for
        for (int i = 0; i < numBlocks; ++i) {
            encryptBlockAES(buffer.data() + (std::size_t(i) * AES_BLOCK_SIZE), expandedKey.data(), numRounds, key, keyWordSize);
        }
        par_end_time = omp_get_wtime();
        
        par_time += par_end_time - par_start_time;

        // Write encrypted data to new file.
        outFile.write(reinterpret_cast<char*>(buffer.data()), dataSize);
    }

    // If the entire file was divisible 
    // by 128-bits then add one extra
    // padded block per PKCS7 standard
    if (fileSize % AES_BLOCK_SIZE == 0) {
        aes::padPKCS7(buffer.data(), AES_BLOCK_SIZE, 0);

        // AES Encryption
        encryptBlockAES(buffer.data(), expandedKey.data(), numRounds, key, keyWordSize);

        // Write encrypted data to new file.
        outFile.write(reinterpret_cast<char*>(buffer.data()), AES_BLOCK_SIZE);
    }

    // Return total time it took to run encrypting parallized
    return par_time;
}

// TODO: Implement.  Mimic structure of 'encrypt..._seq' function above.
//       Instead of encryptBlockAES(), call decryptBlockAES()
/**
 * @brief Decrypt file using AES sequentially
 *
 * @param inFile Input file stream
 * @param outFile Output file stream
 * @param key Pointer to AES key
 * @param keyWordSize Key size in words
  */
double aes::decryptFileAES_seq(std::ifstream& inFile, std::ofstream& outFile, uint32_t* key, std::size_t keyWordSize) {
    static constexpr int CHUNK_SIZE = AES_BLOCK_SIZE * 2000; // Buffer size for processing

    // Ensure files are open for reading and writing
    assert(inFile.is_open());
    assert(outFile.is_open());

    // Determine the number of AES rounds based on key size
    std::size_t numRounds = getNumbRounds(keyWordSize);

    // Expand the key for all AES rounds
    std::vector<uint32_t> expandedKey((numRounds + 1) * 4, 0);
    expandKey(expandedKey.data(), numRounds, key, keyWordSize);

    // Buffer to store chunks of file data
    std::vector<unsigned char> buffer(CHUNK_SIZE, 0);
    std::streamsize dataSize = 0;

    double seq_start_time = omp_get_wtime();  // Start timing the sequential decryption

    // Read through the file in chunks and decrypt each chunk
    while (!inFile.eof()) {
        inFile.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
        dataSize = inFile.gcount();  // Get the size of the data read into buffer

        const long long numBlocks = dataSize / AES_BLOCK_SIZE;

        // Process each 128-bit block in the chunk
        for (int i = 0; i < numBlocks; ++i) {
            decryptBlockAES(buffer.data() + (std::size_t(i) * AES_BLOCK_SIZE), expandedKey.data(), numRounds, key, keyWordSize);
        }

        // Write decrypted data to output file
        outFile.write(reinterpret_cast<char*>(buffer.data()), dataSize);
    }

    double seq_end_time = omp_get_wtime();  // End timing
    return seq_end_time - seq_start_time;   // Return the time taken for decryption
}

// TODO: Implement.  Mimic structure of 'encrypt..._parallel' function above.
//       Instead of encryptBlockAES(), call decryptBlockAES()
/**
 * @brief Decrypt file using parallelized
 */
double aes::decryptFileAES_parallel( void )
{
    double par_time = 0;

    return par_time;
}


/**
* @brief Encrypts one 16-byte block of the file.
*
* @param buffer Block to be encrypted
* @param expandedKeys Round key array generated from original key
* @param numRounds Number of AES rounds
* @param key Original AES key
* @param keySizeWords Size of AES key in words
* 
* @note See FIPS 197, Section 5.1, Algorithm 1: Cipher()
*/
void aes::encryptBlockAES(unsigned char* buffer, uint32_t* expandedKeys, const std::size_t numRounds, const uint32_t* const key, const std::size_t keySizeWords)
{
    static constexpr int ROUND_KEY_SIZE = 16;

    // Pointer we use to walk roundWords array in 32-bit steps
    uint32_t* roundKey = expandedKeys;

    // Initial Xor: Xor the buffer with the current round key 
    aes::xorByteArray(buffer, reinterpret_cast<unsigned char*>(roundKey), ROUND_KEY_SIZE);

    // Do Rounds 1 through  N-1.
    // N-1 because the last round skips the mixColumns step
    for (int r = 0; r < numRounds - 1; ++r) {

        // S-Box Substitution
        sBoxSubstitution(buffer, AES_BLOCK_SIZE);

        // Shift Rows
        shiftRows(buffer, AES_BLOCK_SIZE, AES_BLOCK_ROWS);

        // Mix Columns
        mixColumns(buffer, AES_BLOCK_SIZE, AES_BLOCK_ROWS);

        // Increment to current roundKey
        // Must add 4 because each round key is 128 bits
        roundKey += 4; // 4 * 32-bit words = 16 bytes = 128 bits

        // Xor the buffer with the current round key
        xorByteArray(buffer, reinterpret_cast<unsigned char*>(roundKey), ROUND_KEY_SIZE);
    }

    // Do Last Round

    // S-Box Substitution
    sBoxSubstitution(buffer, AES_BLOCK_SIZE);

    // Shift Rows
    shiftRows(buffer, AES_BLOCK_SIZE, AES_BLOCK_ROWS);

    // Increment to current roundKey
    // Must add 4 because each round key is 128 bits
    roundKey += 4; // 4 * 32-bit words = 16 bytes = 128 bits

    // Xor the buffer with the current round key
    xorByteArray(buffer, reinterpret_cast<unsigned char*>(roundKey), ROUND_KEY_SIZE);
}



/**
 * @brief Decrypts one 16-byte block of the file.
 *
 * @param buffer Block to be encrypted
 * @param expandedKeys Round key array generated from original key
 * @param numRounds Number of AES rounds
 * @param key Original AES key
 * @param keySizeWords Size of AES key in words
 * 
 * @note See FIPS 197, Section 5.1, Algorithm 1: Cipher()
 */
void aes::decryptBlockAES(unsigned char* buffer, uint32_t* expandedKeys, const std::size_t numRounds, const uint32_t* const key, const std::size_t keySizeWords) {
    static constexpr int ROUND_KEY_SIZE = 16;

    // Start with the last round key
    uint32_t* roundKey = expandedKeys + numRounds * 4;
    xorByteArray(buffer, reinterpret_cast<unsigned char*>(roundKey), ROUND_KEY_SIZE);

    // Perform N-1 rounds in reverse
    for (int r = numRounds - 1; r > 0; --r) {
        //inverseShiftRows(buffer, AES_BLOCK_SIZE, AES_BLOCK_ROWS);
        // inverseSBoxSubstitution(buffer, AES_BLOCK_SIZE);

        roundKey -= 4;  // Move to the previous round key
        xorByteArray(buffer, reinterpret_cast<unsigned char*>(roundKey), ROUND_KEY_SIZE);

        //inverseMixColumns(buffer, AES_BLOCK_SIZE, AES_BLOCK_ROWS);
    }

    // Final round (No InverseMixColumns here)
    //inverseShiftRows(buffer, AES_BLOCK_SIZE, AES_BLOCK_ROWS);
    //inverseSBoxSubstitution(buffer, AES_BLOCK_SIZE);
    xorByteArray(buffer, reinterpret_cast<unsigned char*>(expandedKeys), ROUND_KEY_SIZE);
}


/**
 * @brief Expand AES key into round keys
 *
 * @param expandedKeys Array to store the expanded keys
 * @param numRounds Number of AES rounds
 * @param key Original AES key
 * @param keySize Key size in words
 */
void aes::expandKey(uint32_t* const& expandedKeys, const std::size_t numRounds, const uint32_t* const& key, std::size_t keySize)
{
    // RCON Constant Matrix
    const static unsigned char RCON[10][4] = {
        {0x01, 0x00, 0x00, 0x00},
        {0x02, 0x00, 0x00, 0x00},
        {0x04, 0x00, 0x00, 0x00},
        {0x08, 0x00, 0x00, 0x00},
        {0x10, 0x00, 0x00, 0x00},
        {0x20, 0x00, 0x00, 0x00},
        {0x40, 0x00, 0x00, 0x00},
        {0x80, 0x00, 0x00, 0x00},
        {0x1b, 0x00, 0x00, 0x00},
        {0x36, 0x00, 0x00, 0x00}
    };

    // Round Key = 128-Bits Always
    // Word = 32-Bit Partial Round Key
    // 
    // Initialize First Round Key, w[0] - w[3] on FIPS 197
    std::size_t i = 0;
    for (; i < keySize; i++)
        expandedKeys[i] = key[i];

    // Calculate the number of words needed to 
    // have a round key for each round (numRounds)
    const std::size_t numWords = (numRounds + 1) * 4;

    // Generate Words 
    for (; i < numWords; ++i) {
        uint32_t temp = expandedKeys[i - 1];

        // If the current word is the first word of a round key
        if (i % keySize == 0) {

            // Rotate word left
            rotateWordLeft(temp, 1);

            // S-Box Substitute word
            sBoxSubstitution(reinterpret_cast<unsigned char*>(&temp), 4);

            // Xor word with current RCON value
            temp = temp ^ *reinterpret_cast<const uint32_t*>(RCON[i / keySize - 1]);
        }
        else if (keySize > 6 && i % keySize == 4) {
            // If keySize is 256-Bit and i + 4 is a multiple of 8 
            // S-Box Substitute word
            sBoxSubstitution(reinterpret_cast<unsigned char*>(&temp), 4);
        }

        // Xor word with:
        // * 4th previous word (128-Bit)
        // * 6th previous word (192-Bit)
        // * 8th previous word (256-Bit)
        expandedKeys[i] = expandedKeys[i - keySize] ^ temp;
    }
}

/** Called by encryptFileAES functions*/
void aes::padPKCS7(unsigned char* const& buffer, const std::size_t bufferSize, const unsigned int startPos)
{
    unsigned char padByte = static_cast<unsigned char> (bufferSize - startPos);
    for (std::size_t i = startPos; i < bufferSize; ++i)
        buffer[i] = padByte;
}

/** Called by encryptFileAES functions*/
std::size_t aes::getNumbRounds(std::size_t keySizeWords)
{
    switch (keySizeWords) {
        case KEY_SIZE_WORDS_128:
            return NUM_ROUNDS_128;
        case KEY_SIZE_WORDS_192:
            return NUM_ROUNDS_192;
        case KEY_SIZE_WORDS_256:
            return NUM_ROUNDS_256;
            break;
        default:
            return 0;
    }
}


/**
* @brief Rotate word left by number of bits specified
* Helper function for expandKey()
*
* @param words 32-bit word to rotate
* @param shiftAmount Number of bits to shift
*/
void aes::rotateWordLeft(uint32_t& words, const std::size_t shiftAmount)
{
    int shift = shiftAmount % sizeof(uint32_t);
    if (shift == 0)
        return;

    uint32_t shiftedRight = words >> 8 * shift;
    uint32_t shiftedLeft = words << 8 * (sizeof(uint32_t) - shift);
    words = shiftedRight | shiftedLeft;
}

/**
* See FIPS 197, section 5.1.4: AddRoundKey()
*/
void aes::xorByteArray(unsigned char* buffer, unsigned char* key, std::size_t keySizeBytes)
{
    assert(keySizeBytes % sizeof(uint64_t) == 0);

    // Xor the buffer in as few iterations as possible
    uint64_t* buffer64 = reinterpret_cast<uint64_t*>(buffer);
    uint64_t* key64 = reinterpret_cast<uint64_t*>(key);

    for (int i = 0; i < (keySizeBytes / sizeof(uint64_t)); ++i) {
        *(buffer64 + i) = *(buffer64 + i) ^ *(key64 + i);
    }
}

/** Helper function for mixColumns() */
unsigned char aes::galoisMultiplyBy2(unsigned char value) 
{
    unsigned char result = value << 1;
    if (value & 0x80) { // If the most significant bit is set (overflow)
        result ^= 0x1b; // XOR with the AES irreducible polynomial
    }
    return result;
}

/**
 * @brief Transform buffer by splitting into columns and performing matrix multiplication.
 *
 * @param buffer Data buffer in AES block
 * @param size Buffer size
 * @param rowCount Number of rows in AES block
 * 
 * @note See FIPS 197, Section 5.1.3: MixColumns()
 */
void aes::mixColumns(unsigned char* buffer, const std::size_t size, const std::size_t rowCount)
{
    static const unsigned char COL_MIXER[AES_BLOCK_COLS][AES_BLOCK_ROWS] = {
        {0x02, 0x03, 0x01, 0x01},
        {0x01, 0x02, 0x03, 0x01},
        {0x01, 0x01, 0x02, 0x03},
        {0x03, 0x01, 0x01, 0x02},
    };

    assert(size % rowCount == 0);

    std::vector<unsigned char> mixed = std::vector<unsigned char>(AES_BLOCK_SIZE, 0);
    const std::size_t colCount = size / rowCount;
    for (std::size_t col = 0; col < colCount; ++col) {

        for (std::size_t mixerRow = 0; mixerRow < AES_BLOCK_ROWS; ++mixerRow) {
            unsigned char mixedValue = 0;  // Temporary value to accumulate results
            for (std::size_t mixerCol = 0; mixerCol < AES_BLOCK_COLS; ++mixerCol) {
                unsigned char temp = 0;
                unsigned char value = buffer[col * rowCount + mixerCol];
                switch (COL_MIXER[mixerRow][mixerCol]) {
                case 1:
                    temp = value;
                    break;
                case 2:
                    temp = galoisMultiplyBy2(value);
                    break;
                case 3:
                    temp = galoisMultiplyBy2(value) ^ value;
                    break;
                default:
                    std::cout << "Error: Invalid Constant Array!" << std::endl;
                    return;
                }
                mixedValue ^= temp;
            }
            mixed[col * rowCount + mixerRow] = mixedValue;
        }

    }

    std::copy(mixed.begin(), mixed.end(), buffer);
}

/* UNUSED ? commenting out for now
void aes::shiftCols(uint32_t* const& buffer, const std::size_t rowCount)
{
    for (int row = 1; row < rowCount; ++row) {
        rotateWordLeft(*(buffer + row), row);
    }
}
*/

/**
 * @brief Transforms buffer by splitting into 4 rows and shifting each row a different amount.
 *
 * @param buffer Data buffer in AES block
 * @param size Buffer size
 * @param rowCount Number of rows in AES block
 * 
 * @note See FIPS 197, Section 5.1.2: ShiftRows()
 */
void aes::shiftRows(unsigned char* buffer, const std::size_t size, const std::size_t rowCount)
{
    assert(size % rowCount == 0);

    const std::size_t colCount = size / rowCount;

    // TODO: There's probably a faster way to do this if we are certain the buffer is 16 bytes
    for (std::size_t row = 1; row < rowCount; ++row) {
        std::size_t shift = row;

        // Max of 3 temps with 4x4 blocks
        std::vector<unsigned char> temps = std::vector<unsigned char>(AES_BLOCK_COLS - 1, 0);

        // Copy Temp Values
        for (std::size_t col = 0; col < shift; ++col)
            temps.at(col) = buffer[col * rowCount + row];

        const std::size_t shiftEnd = colCount - shift;

        // Shift old values left
        for (std::size_t col = 0; col < shiftEnd; ++col)
            buffer[col * rowCount + row] = buffer[(col + shift) * rowCount + row];

        // Copy temp values to the back of the array
        for (std::size_t col = shiftEnd; col < colCount; ++col)
            buffer[col * rowCount + row] = temps.at(col - shiftEnd);
    }
}

/**
* Transforms each byte of the 16-byte buffer.
* 
* See FIPS 197 Section 5.1.1: SubBytes()
*/
void aes::sBoxSubstitution(unsigned char* const& buffer, const std::size_t bufferSize)
{
    static const unsigned char sBox[AES_BLOCK_SIZE][AES_BLOCK_SIZE] = {
        {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76} ,
        {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
        {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
        {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
        {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
        {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
        {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
        {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
        {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
        {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
        {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
        {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
        {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
        {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
        {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
        {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16},
    };

    for (std::size_t i = 0; i < bufferSize; ++i) {
        // Least Significant Nibble
        int lsn = buffer[i] & 0x0F;

        // Most Significant Nibble
        int msn = (buffer[i] >> 4) & 0x0F;

        buffer[i] = sBox[msn][lsn];
    }
}

/* OUTPUT FUNCTIONS */

/**
* @brief Prints buffer in row major order
*
* @param buffer Data buffer to print
* @param size Size of buffer
* @param colCount Number of columns
*/
void aes::printBufferRowMajorOrder(const unsigned char* const& buffer, const std::size_t size, const std::size_t colCount)
{
    assert(size % colCount == 0);

    std::size_t rowCount = size / colCount;
    for (std::size_t row = 0; row < rowCount; ++row) {
        for (std::size_t col = 0; col < colCount; ++col) {
            std::cout << std::hex << std::bitset<8>(buffer[row * colCount + col]).to_ulong() << "\t";
        }
        std::cout << std::endl;
    }
}

/**
 * @brief Prints buffer in row major order
 *
 * @param buffer Data buffer to print
 * @param size Size of buffer
 * @param colCount Number of columns
 */
void aes::printBufferColMajorOrder(const unsigned char* const& buffer, const std::size_t size, const unsigned int colCount)
{
    assert(size % colCount == 0);

    std::size_t rowCount = size / colCount;
    for (std::size_t row = 0; row < rowCount; ++row) {
        for (unsigned int col = 0; col < colCount; ++col) {
            std::cout << std::hex << std::bitset<8>(buffer[col * rowCount + row]).to_ulong() << "\t";
        }
        std::cout << std::endl;
    }
}

/**
 * @brief Compare two files
 *
 * @param path1 Path to first file
 * @param path2 Path to second file
 *
 * @return True if files are identical, else false
 */
bool aes::compareFiles(const std::string& path1, const std::string& path2)
{
    std::ifstream f1(path1, std::ifstream::binary | std::ifstream::ate);
    std::ifstream f2(path2, std::ifstream::binary | std::ifstream::ate);

    if (f1.fail() || f2.fail()) {
        return false; //file problem
    }

    if (f1.tellg() != f2.tellg()) {
        return false; //size mismatch
    }

    //seek back to beginning and use std::equal to compare contents
    f1.seekg(0, std::ifstream::beg);
    f2.seekg(0, std::ifstream::beg);
    return std::equal(std::istreambuf_iterator<char>(f1.rdbuf()),
        std::istreambuf_iterator<char>(),
        std::istreambuf_iterator<char>(f2.rdbuf()));
}