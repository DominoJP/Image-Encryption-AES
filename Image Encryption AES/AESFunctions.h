#pragma once
#include <stdint.h>
#include <vector>
#include <fstream>

constexpr auto AES_BLOCK_SIZE = 16;
constexpr auto AES_BLOCK_COLS = 4;
constexpr auto AES_BLOCK_ROWS = 4;

constexpr auto NUM_ROUNDS_128 = 10;
constexpr auto KEY_SIZE_BITS_128 = 128;
constexpr auto KEY_SIZE_BYTES_128 = KEY_SIZE_BITS_128 / (sizeof(unsigned char) * 8);
constexpr auto KEY_SIZE_WORDS_128 = KEY_SIZE_BITS_128 / (sizeof(uint32_t) * 8);

constexpr auto NUM_ROUNDS_192 = 12;
constexpr auto KEY_SIZE_BITS_192 = 192;
constexpr auto KEY_SIZE_BYTES_192 = KEY_SIZE_BITS_192 / (sizeof(unsigned char) * 8);
constexpr auto KEY_SIZE_WORDS_192 = KEY_SIZE_BITS_192 / (sizeof(uint32_t) * 8);

constexpr auto NUM_ROUNDS_256 = 14;
constexpr auto KEY_SIZE_BITS_256 = 256;
constexpr auto KEY_SIZE_BYTES_256 = KEY_SIZE_BITS_256 / (sizeof(unsigned char) * 8);
constexpr auto KEY_SIZE_WORDS_256 = KEY_SIZE_BITS_256 / (sizeof(uint32_t) * 8);

namespace aes 
{
	// AES Function Declarations

	double encryptFileAES_seq(std::ifstream& inFile, std::ofstream& outFile, uint32_t* key, std::size_t keyWordSize);
	double encryptFileAES_parallel(std::ifstream& inFile, std::ofstream& outFile, uint32_t* key, std::size_t keyWordSize);
	double decryptFileAES_seq( void );  // TODO  arguments
	double decryptFileAES_parallel( void );  // TODO  arguments

	void encryptBlockAES(unsigned char* buffer, uint32_t* expandedKeys, const std::size_t numRounds, const uint32_t* const key, const std::size_t keySizeWords);

	void expandKey(uint32_t* const& expandedKeys, const std::size_t numRounds, const uint32_t* const& key, std::size_t keySize);

	void padPKCS7(unsigned char* const& buffer, const std::size_t bufferSize, const unsigned int startPos);

	std::size_t getNumbRounds(std::size_t keySizeWords);

	void rotateWordLeft(uint32_t& words, const std::size_t shiftAmount);

	void xorByteArray(unsigned char* buffer, unsigned char* key, std::size_t keySizeBytes);

	unsigned char galoisMultiplyBy2(unsigned char value);	

	void mixColumns(unsigned char* buffer, const std::size_t size, const std::size_t rowCount);

	void shiftRows(unsigned char* buffer, const std::size_t size, const std::size_t rowCount);

	void shiftCols(uint32_t* const& buffer, const std::size_t rowCount);

	void sBoxSubstitution(unsigned char* const& buffer, const std::size_t bufferSize);

	void printBufferRowMajorOrder(const unsigned char* const& buffer, const std::size_t size, const std::size_t colCount);

	void printBufferColMajorOrder(const unsigned char* const& buffer, const std::size_t size, const unsigned int colCount);

	bool compareFiles(const std::string& path1, const std::string& path2);
}