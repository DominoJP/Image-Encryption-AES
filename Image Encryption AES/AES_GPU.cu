#include <cuda_runtime.h>
#include "device_launch_parameters.h"

#include "AES_GPU.cuh"
#include "AESFunctions.h"

//starts at the chunk and sends each block to a thread to be encrypted
__global__ void AES_GPU::encryptChunkAES_GPU(unsigned char* chunk, unsigned int* expandedKey, unsigned __int64 numRounds, unsigned char* key, unsigned __int64 keyWordSize) {
    int i = threadIdx.x;
    unsigned __int64 offset = i * AES_BLOCK_SIZE;

    encryptBlockAES_GPU(chunk + offset, expandedKey, numRounds, key, keyWordSize);
}

__device__ void AES_GPU::encryptBlockAES_GPU(unsigned char* buffer, unsigned int* expandedKeys, unsigned __int64 numRounds, unsigned char* key, unsigned __int64 keySizeWords)
{
    static constexpr int ROUND_KEY_SIZE = 16;

    // Pointer we use to walk roundWords array in 32-bit steps
    uint32_t* roundKey = expandedKeys;

    // Initial Xor: Xor the buffer with the current round key 
    xorByteArray_GPU(buffer, reinterpret_cast<unsigned char*>(roundKey), ROUND_KEY_SIZE);

    // Do Rounds 1 through  N-1.
    // N-1 because the last round skips the mixColumns step
    for (int r = 0; r < numRounds - 1; ++r) {

        // S-Box Substitution
        sBoxSubstitution_GPU(buffer, AES_BLOCK_SIZE);

        // Shift Rows
        shiftRows_GPU(buffer, AES_BLOCK_SIZE, AES_BLOCK_ROWS);

        // Mix Columns
        mixColumns_GPU(buffer, AES_BLOCK_SIZE, AES_BLOCK_ROWS);

        // Increment to current roundKey
        // Must add 4 because each round key is 128 bits
        roundKey += 4; // 4 * 32-bit words = 16 bytes = 128 bits

        // Xor the buffer with the current round key
        xorByteArray_GPU(buffer, reinterpret_cast<unsigned char*>(roundKey), ROUND_KEY_SIZE);
    }

    // Do Last Round

    // S-Box Substitution
    sBoxSubstitution_GPU(buffer, AES_BLOCK_SIZE);

    // Shift Rows
    shiftRows_GPU(buffer, AES_BLOCK_SIZE, AES_BLOCK_ROWS);

    // Increment to current roundKey
    // Must add 4 because each round key is 128 bits
    roundKey += 4; // 4 * 32-bit words = 16 bytes = 128 bits

    // Xor the buffer with the current round key
    xorByteArray_GPU(buffer, reinterpret_cast<unsigned char*>(roundKey), ROUND_KEY_SIZE);
}

__device__ void AES_GPU::sBoxSubstitution_GPU(unsigned char* const& buffer, const std::size_t bufferSize)
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

    for (size_t i = 0; i < bufferSize; ++i) {
        // Least Significant Nibble
        int lsn = buffer[i] & 0x0F;

        // Most Significant Nibble
        int msn = (buffer[i] >> 4) & 0x0F;

        buffer[i] = sBox[msn][lsn];
    }
}

__device__ void AES_GPU::shiftRows_GPU(unsigned char* buffer, const std::size_t size, const std::size_t rowCount)
{
    if (size % rowCount != 0) {
        printf("error occured in shiftRows_GPU ");
    }

    const size_t colCount = size / rowCount;

    // TODO: There's probably a faster way to do this if we are certain the buffer is 16 bytes
    for (size_t row = 1; row < rowCount; ++row) {
        size_t shift = row;

        // Max of 3 temps with 4x4 blocks
        unsigned char* temps = reinterpret_cast<unsigned char*>(AES_BLOCK_COLS - 1, 0);

        // Copy Temp Values
        for (size_t col = 0; col < shift; ++col)
            temps[col] = buffer[col * rowCount + row];

        const std::size_t shiftEnd = colCount - shift;

        // Shift old values left
        for (size_t col = 0; col < shiftEnd; ++col)
            buffer[col * rowCount + row] = buffer[(col + shift) * rowCount + row];

        // Copy temp values to the back of the array
        for (size_t col = shiftEnd; col < colCount; ++col)
            buffer[col * rowCount + row] = temps[col - shiftEnd];
    }
}

__device__ void AES_GPU::mixColumns_GPU(unsigned char* buffer, const size_t size, const size_t rowCount)
{
    static const unsigned char COL_MIXER[AES_BLOCK_COLS][AES_BLOCK_ROWS] = {
        {0x02, 0x03, 0x01, 0x01},
        {0x01, 0x02, 0x03, 0x01},
        {0x01, 0x01, 0x02, 0x03},
        {0x03, 0x01, 0x01, 0x02},
    };

    //assert(size % rowCount == 0);
    if (size % rowCount != 0)
        printf("error occured at mixColumns");

    unsigned char* mixed = reinterpret_cast<unsigned char*>(AES_BLOCK_SIZE, 0);
    const size_t colCount = size / rowCount;
    for (size_t col = 0; col < colCount; ++col) {

        for (size_t mixerRow = 0; mixerRow < AES_BLOCK_ROWS; ++mixerRow) {
            unsigned char mixedValue = 0;  // Temporary value to accumulate results
            for (size_t mixerCol = 0; mixerCol < AES_BLOCK_COLS; ++mixerCol) {
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
                    printf("Error: Invalid Constant Array!");
                    return;
                }
                mixedValue ^= temp;
            }
            mixed[col * rowCount + mixerRow] = mixedValue;
        }

    }

    /*std::copy(mixed.begin(), mixed.end(), buffer);*/
    buffer = mixed;
}


/** Helper function for mixColumns() */
__device__ unsigned char AES_GPU::galoisMultiplyBy2(unsigned char value)
{
    unsigned char result = value << 1;
    if (value & 0x80) { // If the most significant bit is set (overflow)
        result ^= 0x1b; // XOR with the AES irreducible polynomial
    }
    return result;
}

__device__ void AES_GPU::xorByteArray_GPU(unsigned char* buffer, unsigned char* key, std::size_t keySizeBytes)
{
    //assert(keySizeBytes % sizeof(uint64_t) == 0);
    if (keySizeBytes % sizeof(uint64_t) != 0)
        printf("error occured at xorByteArray");

    // Xor the buffer in as few iterations as possible
    uint64_t* buffer64 = reinterpret_cast<uint64_t*>(buffer);
    uint64_t* key64 = reinterpret_cast<uint64_t*>(key);

    for (int i = 0; i < (keySizeBytes / sizeof(uint64_t)); ++i) {
        *(buffer64 + i) = *(buffer64 + i) ^ *(key64 + i);
    }
}