// AESProject.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <fstream>
#include <vector>
#include <bitset>
#include <cassert>
#include <stdint.h>

#define AES_BLOCK_SIZE 16
#define AES_BLOCK_COLS 4
#define AES_BLOCK_ROWS 4
#define BUFFER_SIZE AES_BLOCK_SIZE
#define KEY_SIZE 128
#define KEY_CHAR_SIZE KEY_SIZE / (sizeof(unsigned char) * 8)

unsigned char KEY[KEY_CHAR_SIZE] = {
    0x54, 0x68, 0x61, 0x74,
    0x73, 0x20, 0x6D, 0x79,
    0x20, 0x4B, 0x75, 0x6E,
    0x67, 0x20, 0x46, 0x75
    /*
    0x2b, 0x7e, 0x15, 0x16,
    0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88,
    0x09, 0xcf, 0x4f, 0x3c
    /*
    0x, 0x, 0x, 0x,
    0x, 0x, 0x, 0x,
    0x, 0x, 0x, 0x,
    0x, 0x, 0x, 0x
    /*
    0x63, 0x7c, 0x77, 0x7b,
    0xf2, 0x6b, 0x6f, 0xc5,
    0xfa, 0x59, 0x47, 0xf0,
    0x30, 0x01, 0x67, 0x2b
    /*
    0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d,
    0xad, 0xd4, 0xa2, 0xaf,
    0x9c, 0xa4, 0x72, 0xc0
    */
};

const int KEY_WORDS_SIZE = KEY_SIZE / (sizeof(uint32_t) * 8);
uint32_t* KEY_WORDS = reinterpret_cast<uint32_t*>(KEY);

unsigned char RCON[10][4] = {
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

uint32_t roundWords[11 * 4] = { 0 };

// Function Declarations
bool testKnown();
int testFunc(char* fileName);
void sBoxSubstitution(unsigned char* const& buffer, const int bufferSize);
void rotateWordsLeft(uint32_t& words, const int shiftAmount);
void shiftCols(uint32_t* const& buffer, const int rowCount);
void shiftRows(std::vector<unsigned char>& buffer, const int rowCount);
void xorByteArray(unsigned char* buffer, unsigned char* key, int keySizeBytes);
void print2DBuffer(const std::vector<unsigned char>& buffer, const int rowCount);
void print2DBuffer(const unsigned char* const& buffer, const int size, const int rowCount);
std::vector<unsigned char> mixColumns(std::vector<unsigned char>& buffer, const int rowCount);
void expandKeys(uint32_t* const& roundWords, int numRounds, const uint32_t* const& key, int keySize);
void encryptBlock(std::vector<unsigned char>& buffer, uint32_t* roundWords, const int numRounds, const uint32_t* const key, const int keySizeWords);

int main(int argc, char* argv[])
{
    if (argc != 3) {
        std::cout << "Error: incorrect number of arguments! Found " << argc << "." << std::endl;
        return 1;
    }

    std::vector<unsigned char> buffer = std::vector<unsigned char>(BUFFER_SIZE, 0);

    std::ifstream fin(argv[1], std::ifstream::binary);
    if (!fin.is_open()) {
        std::cout << "Error: could not open file " << argv[1] << std::endl;
        return 1;
    }

    std::cout << "Read File: " << argv[1] << std::endl;

    //testFunc(argv[1]);

    // Generate keys for each round
    expandKeys(roundWords, 10, KEY_WORDS, KEY_WORDS_SIZE);

    //while (!fin.eof()) 
    if (false && !fin.eof()) {
        fin.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
        std::streamsize s = fin.gcount();

        std::cout << "Original Data: \n";
        print2DBuffer(buffer, AES_BLOCK_ROWS);

        encryptBlock(buffer, roundWords, 10, KEY_WORDS, KEY_WORDS_SIZE);

        std::cout << "Encrypted Data: \n";
        print2DBuffer(buffer, AES_BLOCK_ROWS);
    }

    // Done and close.
    fin.close();

    testKnown();

    return 0;
}


void encryptBlock(std::vector<unsigned char> &buffer, uint32_t* roundWords, const int numRounds, const uint32_t* const key, const int keySizeWords)
{
    // Ensure buffer size is 16 bytes (128 bits)
    assert(buffer.size() == 16);

    uint32_t* roundKey = roundWords;

    xorByteArray(buffer.data(), reinterpret_cast<unsigned char*>(roundKey), 16);

    for (int r = 0; r < numRounds - 1; ++r) {
        sBoxSubstitution(buffer.data(), buffer.size());
        shiftRows(buffer, AES_BLOCK_ROWS);
        buffer = mixColumns(buffer, AES_BLOCK_ROWS);
        
        // Increment to next roundKey
        // Must add 4 because each round key is 128 bits
        roundKey += 4; // 4 * 32-bit words = 16 bytes = 128 bits
        xorByteArray(buffer.data(), reinterpret_cast<unsigned char*>(roundKey), 16);
    }

    sBoxSubstitution(buffer.data(), buffer.size());
    shiftRows(buffer, AES_BLOCK_ROWS);

    // Increment to next roundKey
    // Must add 4 because each round key is 128 bits
    roundKey += 4; // 4 * 32-bit words = 16 bytes = 128 bits
    xorByteArray(buffer.data(), reinterpret_cast<unsigned char*>(roundKey), 16);
}
void expandKeys(uint32_t* const& roundWords, int numRounds, const uint32_t* const& key, int keySize)
{
    int i = 0;
    for (; i < keySize; i++)
        roundWords[i] = key[i];

    int numWords = (numRounds + 1) * 4;
    for (; i < numWords; ++i) {
        uint32_t temp = roundWords[i - 1];
        if (i % keySize == 0) {
            rotateWordsLeft(temp, 1);
            sBoxSubstitution(reinterpret_cast<unsigned char*>(&temp), 4);
            temp = temp ^ *reinterpret_cast<uint32_t*>(RCON[i / keySize - 1]);
        }
        else if (keySize > 6 && i % keySize == 4) {
            sBoxSubstitution(reinterpret_cast<unsigned char*>(&temp), 4);
        }
        roundWords[i] = roundWords[i - keySize] ^ temp;
    }
}

void rotateWordsLeft(uint32_t& words, const int shiftAmount)
{
    int shift = shiftAmount % sizeof(uint32_t);
    if (shift == 0)
        return;

    uint32_t shiftedRight = words >> 8 * shift;
    uint32_t shiftedLeft = words << 8 * (sizeof(uint32_t) - shift);
    words = shiftedRight | shiftedLeft;
}

void xorByteArray(unsigned char* buffer, unsigned char* key, int keySizeBytes)
{
    assert(keySizeBytes % sizeof(uint64_t) == 0);

    // Xor the buffer in as few iterations as possible
    uint64_t* buffer64 = reinterpret_cast<uint64_t*>(buffer);
    uint64_t* key64 = reinterpret_cast<uint64_t*>(key);

    for (int i = 0; i < (keySizeBytes / sizeof(uint64_t)); ++i) {
        *(buffer64 + i) = *(buffer64 + i) ^ *(key64 + i);
    }
}

unsigned char galoisMultiplyBy2(unsigned char value) {
    unsigned char result = value << 1;
    if (value & 0x80) { // If the most significant bit is set (overflow)
        result ^= 0x1b; // XOR with the AES irreducible polynomial
    }
    return result;
}

std::vector<unsigned char> mixColumns(std::vector<unsigned char>& buffer, const int rowCount)
{
    static const unsigned char COL_MIXER[AES_BLOCK_COLS][AES_BLOCK_ROWS] = {
        {0x02, 0x03, 0x01, 0x01},
        {0x01, 0x02, 0x03, 0x01},
        {0x01, 0x01, 0x02, 0x03},
        {0x03, 0x01, 0x01, 0x02},
    };

    assert(buffer.size() % rowCount == 0);

    std::vector<unsigned char> mixed = std::vector<unsigned char>(BUFFER_SIZE, 0);
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

void shiftCols(uint32_t* const& buffer, const int rowCount)
{
    for (int row = 1; row < rowCount; ++row) {
        rotateWordsLeft(*(buffer + row), row);
    }
}

void shiftRows(std::vector<unsigned char>& buffer, const int rowCount)
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

void sBoxSubstitution(unsigned char* const& buffer, const int bufferSize)
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

void print2DBuffer(const std::vector<unsigned char>& buffer, const int rowCount)
{
    assert(buffer.size() % rowCount == 0);

    int colCount = buffer.size() / rowCount;
    for (int row = 0; row < rowCount; ++row) {
        for (int col = 0; col < colCount; ++col) {
            std::cout << std::hex << std::bitset<8>(buffer.at(col * rowCount + row)).to_ulong() << "\t";
            //std::cout << std::hex << static_cast<unsigned>(buffer[col * colCount + row]) << "\t";
        }
        std::cout << std::endl;
    }
}


void print2DBuffer(const unsigned char* const& buffer, const int size, const int colCount)
{
    assert(size % colCount == 0);

    int rowCount = size / colCount;
    for (int col = 0; col < rowCount; ++col) {
        for (int row = 0; row < colCount; ++row) {
            std::cout << std::hex << static_cast<unsigned>(buffer[col * colCount + row]) << "\t";
        }
        std::cout << std::endl;
    }
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
    expandKeys(roundWords, 10, KNOWN_KEY_WORDS, KNOWN_KEY_WORDS_SIZE);

    std::cout << "\nKey: \n";
    print2DBuffer(KNOWN_KEY, KEY_CHAR_SIZE, 16);

    std::cout << "\nOriginal Data: \n";
    print2DBuffer(dataBuffer.data(), dataBuffer.size(), 16);

    std::cout << "\nExpected Encryption: \n";
    print2DBuffer(EXPECTED_ENCRYPTION, KEY_CHAR_SIZE, 16);

    encryptBlock(dataBuffer, roundWords, 10, KNOWN_KEY_WORDS, KNOWN_KEY_WORDS_SIZE);

    std::cout << "\nEncrypted Data: \n";
    print2DBuffer(dataBuffer.data(), dataBuffer.size(), 16);
    
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

int testFunc(char* fileName)
{
    std::vector<unsigned char> buffer = std::vector<unsigned char>(BUFFER_SIZE, 0);

    std::ifstream fin(fileName, std::ifstream::binary);
    if (!fin.is_open()) {
        std::cout << "Error: could not open file " << fileName << std::endl;
        return 1;
    }

    std::cout << "Read File: " << fileName << std::endl;

    if (!fin.eof()) {
        fin.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
        std::streamsize s = fin.gcount();


        std::cout << "Bytes Read: ";
        for (unsigned char c : buffer)
            std::cout << std::bitset<8>(c) << " ";
        std::cout << std::endl;

        std::cout << "2D Print: " << std::endl;
        print2DBuffer(buffer, AES_BLOCK_ROWS);

        std::cout << "S-Subbed: \n";
        sBoxSubstitution(buffer.data(), buffer.size());
        print2DBuffer(buffer, AES_BLOCK_ROWS);

        std::cout << "Shifted Rows1: \n";
        shiftRows(buffer, AES_BLOCK_ROWS);
        print2DBuffer(buffer, AES_BLOCK_ROWS);

        std::cout << "Mixed Cols: \n" << std::endl;
        buffer = mixColumns(buffer, AES_BLOCK_ROWS);
        print2DBuffer(buffer, AES_BLOCK_ROWS);

        std::cout << "Xor With: " << std::endl;
        for (unsigned char c : KEY) {
            std::cout << std::bitset<8>(c) << " ";
        }
        std::cout << std::endl;
        xorByteArray(buffer.data(), KEY, KEY_CHAR_SIZE);
        print2DBuffer(buffer, AES_BLOCK_ROWS);

        uint32_t* RCON_WORDS = reinterpret_cast<uint32_t*>(RCON);
        unsigned char test[4] = { 0x09, 0xcf, 0xf4, 0x3c };
        std::cout << std::endl;
        for (unsigned char c : test) {
            std::cout << static_cast<int>(c) << "\t";
        }
        std::cout << std::endl;
        uint32_t* TEST_WORDS = reinterpret_cast<uint32_t*>(test);
        rotateWordsLeft(*TEST_WORDS, 5);
        std::cout << std::endl;
        for (unsigned char c : test) {
            std::cout << static_cast<int>(c) << "\t";
        }
        std::cout << std::endl;

        std::cout << "Key: " << std::endl;
        print2DBuffer(KEY, KEY_CHAR_SIZE, 4);
        std::cout << "Round Keys: " << std::endl;
        expandKeys(roundWords, 10, KEY_WORDS, KEY_WORDS_SIZE);
        print2DBuffer(reinterpret_cast<unsigned char*>(roundWords), 176, 16);

        std::cout << std::dec << std::bitset<8>(0x57) << std::endl;
        std::cout << std::dec << std::bitset<8>(0x57 << 1) << std::endl;

    }

    fin.close();
    return 0;
}