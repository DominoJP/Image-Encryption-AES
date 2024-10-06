#pragma once
#include <stdint.h>
#include <vector>
#include <fstream>

#define AES_BLOCK_SIZE 16
#define AES_BLOCK_COLS 4
#define AES_BLOCK_ROWS 4

namespace aes 
{
	// AES Function Declarations

	void encryptFileAES(std::ifstream& inFile, std::ofstream& outFile, uint32_t* key, int keyWordSize);

	void encryptBlockAES(std::vector<unsigned char>& buffer, uint32_t* roundWords, const int numRounds, const uint32_t* const key, const int keySizeWords);
	
	void expandKeys(uint32_t* const& roundWords, int numRounds, const uint32_t* const& key, int keySize);

	void rotateWordsLeft(uint32_t& words, const int shiftAmount);

	void xorByteArray(unsigned char* buffer, unsigned char* key, int keySizeBytes);

	unsigned char galoisMultiplyBy2(unsigned char value);	
	
	std::vector<unsigned char> mixColumns(std::vector<unsigned char>& buffer, const int rowCount);

	void shiftCols(uint32_t* const& buffer, const int rowCount);

	void shiftRows(std::vector<unsigned char>& buffer, const int rowCount);

	void sBoxSubstitution(unsigned char* const& buffer, const int bufferSize);

	void print2DBuffer(const unsigned char* const& buffer, const int size, const int rowCount);
}