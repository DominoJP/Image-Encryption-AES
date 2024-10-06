#include "AESFunctions.h"

#include <iostream>
#include <bitset>
#include <cassert>


void aes::encryptFileAES(std::ifstream & inFile, std::ofstream & outFile, uint32_t* key, int keyWordSize)
{
    std::vector<unsigned char> buffer = std::vector<unsigned char>(AES_BLOCK_SIZE, 0);

    // Generate keys for each round (ASSUMES 128-Bit KEY!!!!)
    // TODO: Make flexible based on key size
    uint32_t roundWords[11 * 4] = { 0 };
    expandKeys(roundWords, 10, key, keyWordSize);

    while (!inFile.eof()) {
        // Read block
        inFile.read(reinterpret_cast<char*>(buffer.data()), buffer.size());

        // Get size of data read
        std::streamsize s = inFile.gcount();

        // If the block is less than 128-bits pad it.
        // Scheme: ISO/IEC 7816-4
        // Should probably go with PKCS#7 padding but lazy
        if (s < AES_BLOCK_SIZE) {
            buffer[s] = 0x80;
            for (++s; s < buffer.size(); ++s)
                buffer[s] = 0x00;

            // Debug Print
            std::cout << "Padded Last Block: \n";
            print2DBuffer(buffer.data(), buffer.size(), AES_BLOCK_ROWS);
        }

        // AES Encryption. 10 rounds using 128-bit key.
        encryptBlockAES(buffer, roundWords, 10, key, keyWordSize);

        // Write encrypted data to new file.
        outFile.write(reinterpret_cast<char*>(buffer.data()), buffer.size());
    }
}

void aes::encryptBlockAES(std::vector<unsigned char>& buffer, uint32_t* roundWords, const int numRounds, const uint32_t* const key, const int keySizeWords)
{
    static const int ROUND_KEY_SIZE = 16;

    // Ensure buffer size is 16 bytes (128 bits)
    assert(buffer.size() == ROUND_KEY_SIZE);

    // Pointer we use to walk roundWords array in 32-bit steps
    uint32_t* roundKey = roundWords;

    // Initial Xor: Xor the buffer with the current round key 
    aes::xorByteArray(buffer.data(), reinterpret_cast<unsigned char*>(roundKey), ROUND_KEY_SIZE);

    // Do Rounds 1 through  N-1.
    // N-1 because the last round skips the mixColumns step
    for (int r = 0; r < numRounds - 1; ++r) {

        // S-Box Substitution
        sBoxSubstitution(buffer.data(), buffer.size());

        // Shift Rows
        shiftRows(buffer, AES_BLOCK_ROWS);

        // Mix Columns
        buffer = mixColumns(buffer, AES_BLOCK_ROWS);

        // Increment to current roundKey
        // Must add 4 because each round key is 128 bits
        roundKey += 4; // 4 * 32-bit words = 16 bytes = 128 bits

        // Xor the buffer with the current round key
        xorByteArray(buffer.data(), reinterpret_cast<unsigned char*>(roundKey), ROUND_KEY_SIZE);
    }

    // Do Last Round

    // S-Box Substitution
    sBoxSubstitution(buffer.data(), buffer.size());

    // Shift Rows
    shiftRows(buffer, AES_BLOCK_ROWS);

    // Increment to current roundKey
    // Must add 4 because each round key is 128 bits
    roundKey += 4; // 4 * 32-bit words = 16 bytes = 128 bits

    // Xor the buffer with the current round key
    xorByteArray(buffer.data(), reinterpret_cast<unsigned char*>(roundKey), ROUND_KEY_SIZE);
}

void aes::expandKeys(uint32_t* const& roundWords, int numRounds, const uint32_t* const& key, int keySize)
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

    // Round Key = 128-Bits
    // Word = 32-Bit Partial Round Key
    // 
    // Initialize First Round Key, w[0] - w[3] on FIPS 197
    int i = 0;
    for (; i < keySize; i++)
        roundWords[i] = key[i];

    // Calculate the number of words needed to 
    // have a round key for each round (numRounds)
    int numWords = (numRounds + 1) * 4;

    // Generate Words 
    for (; i < numWords; ++i) {
        uint32_t temp = roundWords[i - 1];

        // If the current word is the first word of a round key
        if (i % keySize == 0) {

            // Rotate word left
            rotateWordsLeft(temp, 1);

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
        roundWords[i] = roundWords[i - keySize] ^ temp;
    }
}

void aes::rotateWordsLeft(uint32_t& words, const int shiftAmount)
{
    int shift = shiftAmount % sizeof(uint32_t);
    if (shift == 0)
        return;

    uint32_t shiftedRight = words >> 8 * shift;
    uint32_t shiftedLeft = words << 8 * (sizeof(uint32_t) - shift);
    words = shiftedRight | shiftedLeft;
}

void aes::xorByteArray(unsigned char* buffer, unsigned char* key, int keySizeBytes)
{
    assert(keySizeBytes % sizeof(uint64_t) == 0);

    // Xor the buffer in as few iterations as possible
    uint64_t* buffer64 = reinterpret_cast<uint64_t*>(buffer);
    uint64_t* key64 = reinterpret_cast<uint64_t*>(key);

    for (int i = 0; i < (keySizeBytes / sizeof(uint64_t)); ++i) {
        *(buffer64 + i) = *(buffer64 + i) ^ *(key64 + i);
    }
}

unsigned char aes::galoisMultiplyBy2(unsigned char value) {
    unsigned char result = value << 1;
    if (value & 0x80) { // If the most significant bit is set (overflow)
        result ^= 0x1b; // XOR with the AES irreducible polynomial
    }
    return result;
}

std::vector<unsigned char> aes::mixColumns(std::vector<unsigned char>& buffer, const int rowCount)
{
    static const unsigned char COL_MIXER[AES_BLOCK_COLS][AES_BLOCK_ROWS] = {
        {0x02, 0x03, 0x01, 0x01},
        {0x01, 0x02, 0x03, 0x01},
        {0x01, 0x01, 0x02, 0x03},
        {0x03, 0x01, 0x01, 0x02},
    };

    assert(buffer.size() % rowCount == 0);

    std::vector<unsigned char> mixed = std::vector<unsigned char>(AES_BLOCK_SIZE, 0);
    int colCount = buffer.size() / rowCount;
    for (int col = 0; col < colCount; ++col) {

        for (int mixerRow = 0; mixerRow < AES_BLOCK_ROWS; ++mixerRow) {
            unsigned char mixedValue = 0;  // Temporary value to accumulate results
            for (int mixerCol = 0; mixerCol < AES_BLOCK_COLS; ++mixerCol) {
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
                    return std::vector<unsigned char>();
                }
                mixedValue ^= temp;
            }
            mixed[col * rowCount + mixerRow] = mixedValue;
        }

    }

    return mixed;
}

void aes::shiftCols(uint32_t* const& buffer, const int rowCount)
{
    for (int row = 1; row < rowCount; ++row) {
        rotateWordsLeft(*(buffer + row), row);
    }
}

void aes::shiftRows(std::vector<unsigned char>& buffer, const int rowCount)
{
    assert(buffer.size() % rowCount == 0);

    int colCount = buffer.size() / rowCount;
    for (int row = 1; row < rowCount; ++row) {
        int shift = row;

        // Max of 3 temps with 4x4 blocks
        std::vector<unsigned char> temps = std::vector<unsigned char>(AES_BLOCK_COLS - 1, 0);

        // Copy Temp Values
        for (int col = 0; col < shift; ++col)
            temps.at(col) = buffer.at(col * rowCount + row);


        int shiftEnd = colCount - shift;

        // Shift old values left
        for (int col = 0; col < shiftEnd; ++col)
            buffer.at(col * rowCount + row) = buffer.at((col + shift) * rowCount + row);

        // Copy temp values to the back of the array
        for (int col = shiftEnd; col < colCount; ++col)
            buffer.at(col * rowCount + row) = temps.at(col - shiftEnd);
    }
}

void aes::sBoxSubstitution(unsigned char* const& buffer, const int bufferSize)
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

    for (int i = 0; i < bufferSize; ++i) {
        // Least Significant Nibble
        int lsn = buffer[i] & 0x0F;

        // Most Significant Nibble
        int msn = (buffer[i] >> 4) & 0x0F;

        buffer[i] = sBox[msn][lsn];
    }
}


void aes::print2DBuffer(const unsigned char* const& buffer, const int size, const int colCount)
{
    assert(size % colCount == 0);

    int rowCount = size / colCount;
    for (int col = 0; col < rowCount; ++col) {
        for (int row = 0; row < colCount; ++row) {
            std::cout << std::hex << std::bitset<8>(buffer[col * rowCount + row]).to_ulong() << "\t";
        }
        std::cout << std::endl;
    }
}