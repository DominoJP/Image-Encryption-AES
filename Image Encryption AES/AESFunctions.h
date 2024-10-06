#pragma once
#include <stdint.h>
#include <vector>
#include <fstream>

#define AES_BLOCK_SIZE 16
#define AES_BLOCK_COLS 4
#define AES_BLOCK_ROWS 4

#define NUM_ROUNDS_128 10
#define KEY_SIZE_BITS_128 128
#define KEY_SIZE_BYTES_128 KEY_SIZE_BITS_128 / (sizeof(unsigned char) * 8)
#define KEY_SIZE_WORDS_128 KEY_SIZE_BITS_128 / (sizeof(uint32_t) * 8)

#define NUM_ROUNDS_192 12
#define KEY_SIZE_BITS_192 192
#define KEY_SIZE_BYTES_192 KEY_SIZE_BITS_192 / (sizeof(unsigned char) * 8)
#define KEY_SIZE_WORDS_192 KEY_SIZE_BITS_192 / (sizeof(uint32_t) * 8)

#define NUM_ROUNDS_256 14
#define KEY_SIZE_BITS_256 256
#define KEY_SIZE_BYTES_256 KEY_SIZE_BITS_256 / (sizeof(unsigned char) * 8)
#define KEY_SIZE_WORDS_256 KEY_SIZE_BITS_256 / (sizeof(uint32_t) * 8)

namespace aes 
{
	// AES Function Declarations

	bool encryptFileAES(std::ifstream& inFile, std::ofstream& outFile, uint32_t* key, std::size_t keyWordSize);

	void encryptBlockAES(std::vector<unsigned char>& buffer, uint32_t* expandedKeys, const std::size_t numRounds, const uint32_t* const key, const std::size_t keySizeWords);

	void expandKey(uint32_t* const& expandedKeys, const std::size_t numRounds, const uint32_t* const& key, std::size_t keySize);

	void rotateWordLeft(uint32_t& words, const std::size_t shiftAmount);

	void xorByteArray(unsigned char* buffer, unsigned char* key, std::size_t keySizeBytes);

	unsigned char galoisMultiplyBy2(unsigned char value);	
	
	std::vector<unsigned char> mixColumns(std::vector<unsigned char>& buffer, const std::size_t rowCount);

	void shiftCols(uint32_t* const& buffer, const std::size_t rowCount);

	void shiftRows(std::vector<unsigned char>& buffer, const std::size_t rowCount);

	void sBoxSubstitution(unsigned char* const& buffer, const std::size_t bufferSize);

	void printBufferRowMajorOrder(const unsigned char* const& buffer, const std::size_t size, const std::size_t colCount);

	void printBufferColMajorOrder(const unsigned char* const& buffer, const std::size_t size, const std::size_t colCount);
}