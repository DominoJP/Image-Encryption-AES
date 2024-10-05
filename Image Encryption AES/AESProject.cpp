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
#define KEY_CHAR_SIZE KEY_SIZE / (sizeof(char) * 8)

char KEY[KEY_CHAR_SIZE] = {
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

char RCON[10][4] = {
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

void sBoxSubstitution(char* const& buffer, const int bufferSize);
void rotateWordLeft(uint32_t& words, const int shiftAmount);
void shiftCols(uint32_t* const& buffer, const int rowCount);
void shiftRows(std::vector<char>& buffer, const int rowCount);
void xorByteArray(std::vector<char>& buffer, char* key, int keySize);
void print2DBuffer(const std::vector<char>& buffer, const int rowCount);
void print2DBuffer(const unsigned char* const& buffer, const int size, const int rowCount);
std::vector<char> mixColumns(std::vector<char>& buffer, const int rowCount);
void expandKeys(uint32_t* const& roundWords, int numRounds, const uint32_t* const& key, int keySize);

int main(int argc, char* argv[])
{
    if (argc != 3) {
        std::cout << "Error: incorrect number of arguments! Found " << argc << "." << std::endl;
        return 1;
    }

    std::vector<char> buffer = std::vector<char>(BUFFER_SIZE, 0);

    std::ifstream fin(argv[1], std::ifstream::binary);
    if (!fin.is_open()) {
        std::cout << "Error: could not open file " << argv[0] << std::endl;
        return -1;
    }

    std::cout << "Read File: " << argv[1] << std::endl;

    //while (!fin.eof()) 
    if (!fin.eof()) {
        fin.read(buffer.data(), buffer.size());
        std::streamsize s = fin.gcount();


        std::cout << "Bytes Read: ";
        for (char c : buffer)
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
        for (char c : KEY) {
            std::cout << std::bitset<8>(c) << " ";
        }
        std::cout << std::endl;
        xorByteArray(buffer, KEY, KEY_CHAR_SIZE);
        print2DBuffer(buffer, AES_BLOCK_ROWS);

        uint32_t* RCON_WORDS = reinterpret_cast<uint32_t*>(RCON);
        char test[4] = { 0x09, 0xcf, 0xf4, 0x3c };
        std::cout << std::endl;
        for (char c : test) {
            std::cout << static_cast<int>(c) << "\t";
        }
        std::cout << std::endl;
        uint32_t* TEST_WORDS = reinterpret_cast<uint32_t*>(test);
        rotateWordLeft(*TEST_WORDS, 5);
        std::cout << std::endl;
        for (char c : test) {
            std::cout << static_cast<int>(c) << "\t";
        }
        std::cout << std::endl;

        std::cout << "Key: " << std::endl;
        print2DBuffer(reinterpret_cast<unsigned char*>(KEY), KEY_CHAR_SIZE, 4);
        std::cout << "Round Keys: " << std::endl;
        expandKeys(roundWords, 10, KEY_WORDS, KEY_WORDS_SIZE);
        print2DBuffer(reinterpret_cast<unsigned char*>(roundWords), 176, 16);

    }

    // Done and close.
    fin.close();

    return 0;
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
            rotateWordLeft(temp, 1);
            sBoxSubstitution(reinterpret_cast<char*>(&temp), 4);
            temp = temp ^ *reinterpret_cast<uint32_t*>(RCON[i / keySize - 1]);
        }
        else if (keySize > 6 && i % keySize == 4) {
            sBoxSubstitution(reinterpret_cast<char*>(&temp), 4);
        }
        roundWords[i] = roundWords[i - keySize] ^ temp;
    }
}

void encryptBlock(char* const buffer, const int& key)
{

}

void rotateWordLeft(uint32_t& words, const int shiftAmount)
{
    int shift = shiftAmount % sizeof(uint32_t);
    if (shift == 0)
        return;

    uint32_t shiftedRight = words >> 8 * shift;
    uint32_t shiftedLeft = words << 8 * (sizeof(uint32_t) - shift);
    words = shiftedRight | shiftedLeft;
}

void xorByteArray(std::vector<char>& buffer, char* key, int keySize)
{
    assert(keySize % sizeof(uint64_t) == 0);
    std::cout << "Key Size: " << keySize << " int64: " << sizeof(uint64_t) << std::endl;

    // Xor the buffer in as few iterations as possible
    uint64_t* buffer64 = reinterpret_cast<uint64_t*>(buffer.data());
    uint64_t* key64 = reinterpret_cast<uint64_t*>(key);

    for (int i = 0; i < (keySize / sizeof(uint64_t)); ++i) {
        *(buffer64 + i) = *(buffer64 + i) ^ *(key64 + i);
    }
}

std::vector<char> mixColumns(std::vector<char>& buffer, const int rowCount)
{
    static const char COL_MIXER[AES_BLOCK_COLS][AES_BLOCK_ROWS] = {
        {0x02, 0x03, 0x01, 0x01},
        {0x01, 0x02, 0x03, 0x01},
        {0x01, 0x01, 0x02, 0x03},
        {0x03, 0x01, 0x01, 0x02},
    };

    assert(buffer.size() % rowCount == 0);

    std::vector<char> mixed = std::vector<char>(BUFFER_SIZE, 0);

    int colCount = buffer.size() / rowCount;
    for (int col1 = 0; col1 < colCount; ++col1) {
        for (int row2 = 0; row2 < rowCount; ++row2) {
            for (int col12 = 0; col12 < rowCount; ++col12) {
                mixed[col1 * rowCount + row2] += buffer[col1 * rowCount + col12] * COL_MIXER[row2][col12];
            }
        }
    }

    return mixed;
}

void shiftCols(uint32_t* const& buffer, const int rowCount)
{
    for (int row = 1; row < rowCount; ++row) {
        rotateWordLeft(*(buffer + row), row);
    }
}

void shiftRows(std::vector<char>& buffer, const int rowCount)
{
    assert(buffer.size() % rowCount == 0);

    int colCount = buffer.size() / rowCount;
    for (int row = 1; row < rowCount; ++row) {
        int shift = row;

        // Max of 3 temps with 4x4 blocks
        std::vector<char> temps = std::vector<char>(AES_BLOCK_COLS - 1, 0);

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

void sBoxSubstitution(char* const& buffer, const int bufferSize)
{
    static const char sBox[AES_BLOCK_SIZE][AES_BLOCK_SIZE] = {
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

void print2DBuffer(const std::vector<char>& buffer, const int rowCount)
{
    assert(buffer.size() % rowCount == 0);

    int colCount = buffer.size() / rowCount;
    for (int row = 0; row < rowCount; ++row) {
        for (int col = 0; col < colCount; ++col) {
            std::cout << static_cast<int>(buffer.at(col * rowCount + row)) << "\t";
        }
        std::cout << std::endl;
    }
}


void print2DBuffer(const unsigned char* const& buffer, const int size, const int rowCount)
{
    assert(size % rowCount == 0);

    int colCount = size / rowCount;
    for (int col = 0; col < colCount; ++col) {
        for (int row = 0; row < rowCount; ++row) {
            std::cout << std::hex << static_cast<unsigned>(buffer[col * rowCount + row]) << "\t";
        }
        std::cout << std::endl;
    }
}