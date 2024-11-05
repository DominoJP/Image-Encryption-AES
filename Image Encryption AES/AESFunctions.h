#pragma once
#include <stdint.h>
#include <vector>
#include <fstream>
#include <cstring>

constexpr auto AES_BLOCK_SIZE = 16; /**< AES block size in bytes */
constexpr auto AES_BLOCK_COLS = 4; /**< AES block number of columns  */
constexpr auto AES_BLOCK_ROWS = 4; /**< AES block number of rows */

constexpr auto NUM_ROUNDS_128 = 10; /**< Number of rounds for AES-128 */
constexpr auto KEY_SIZE_BITS_128 = 128; /**< AES-128 in bits key size */
constexpr auto KEY_SIZE_BYTES_128 = KEY_SIZE_BITS_128 / (sizeof(unsigned char) * 8);
constexpr auto KEY_SIZE_WORDS_128 = KEY_SIZE_BITS_128 / (sizeof(uint32_t) * 8);

constexpr auto NUM_ROUNDS_192 = 12; /**< Number of rounds for AES-192 */
constexpr auto KEY_SIZE_BITS_192 = 192; /**< AES-192 in bits key size */
constexpr auto KEY_SIZE_BYTES_192 = KEY_SIZE_BITS_192 / (sizeof(unsigned char) * 8);
constexpr auto KEY_SIZE_WORDS_192 = KEY_SIZE_BITS_192 / (sizeof(uint32_t) * 8);

constexpr auto NUM_ROUNDS_256 = 14; /**< Number of rounds for AES-256 */
constexpr auto KEY_SIZE_BITS_256 = 256; /**< AES-192 in bits key size */
constexpr auto KEY_SIZE_BYTES_256 = KEY_SIZE_BITS_256 / (sizeof(unsigned char) * 8);
constexpr auto KEY_SIZE_WORDS_256 = KEY_SIZE_BITS_256 / (sizeof(uint32_t) * 8);

namespace aes 
{
	// AES Function Declarations

	/**
	 * @brief Encrypt file using AES sequentially
	 * 
	 * @param inFile Input file stream
	 * @param outFile Output file stream
	 * @param key Pointer to AES key
	 * @param keyWordSize Key size in words
	 * 
	 * @return Execution time for encryption
	 */
	double encryptFileAES_seq(std::ifstream& inFile, std::ofstream& outFile, uint32_t* key, std::size_t keyWordSize);

	/**
	 * @brief Encrypt file using AES parallelized
	 *
	 * @param inFile Input file stream
	 * @param outFile Output file stream
	 * @param key Pointer to AES key
	 * @param keyWordSize Key size in words
	 * 
	 * @return Execution time for encryption
	 */
	double encryptFileAES_parallel(std::ifstream& inFile, std::ofstream& outFile, uint32_t* key, std::size_t keyWordSize);

	/**
	 * @brief Decrypt file using AES sequentially
	 *
	 * @param inFile Input file stream
	 * @param outFile Output file stream
	 * @param key Pointer to AES key
	 * @param keyWordSize Key size in words
	 * 
	 * @return Execution time for decryption
	 */
	double decryptFileAES_seq(std::ifstream& inFile, std::ofstream& outFile, uint32_t* key, std::size_t keyWordSize);

	/**
	 * @brief Decrypt file using parallelized
	 * 
	 * @return Execution time for decryption
	 */
	double decryptFileAES_parallel(std::ifstream& inFile, std::ofstream& outFile, uint32_t* key, std::size_t keyWordSize);  // TODO  arguments

	/**
	 * @brief Encrypt a single AES block
	 * 
	 * @param buffer Block to be encrypted
	 * @param expandedKeys Round key array generated from original key
	 * @param numRounds Number of AES rounds
	 * @param key Original AES key
	 * @param keySizeWords Size of AES key in words
	 */
	void encryptBlockAES(unsigned char* buffer, uint32_t* expandedKeys, const std::size_t numRounds, const uint32_t* const key, const std::size_t keySizeWords);
	
	/**
	 * @brief Decrypt a single AES block
	 *
	 * @param buffer Block to be encrypted
	 * @param expandedKeys Round key array generated from original key
	 * @param numRounds Number of AES rounds
	 * @param key Original AES key
	 * @param keySizeWords Size of AES key in words
	 */
	void decryptBlockAES(unsigned char* buffer, uint32_t* expandedKeys, const std::size_t numRounds, const uint32_t* const key, const std::size_t keySizeWords);  // TODO  arguments

	/**
	 * @brief Expand AES key into round keys
	 * 
	 * @param expandedKeys Array to store the expanded keys
	 * @param numRounds Number of AES rounds
	 * @param key Original AES key
	 * @param keySize Key size in words
	 */
	void expandKey(uint32_t* const& expandedKeys, const std::size_t numRounds, const uint32_t* const& key, std::size_t keySize);

	/**
	 * @brief Pads buffer using PKC57 padding scheme
	 * 
	 * @param buffer Pointer to data buffer to be padded
	 * @param bufferSized Total size of buffer
	 * @param startPos Position to begin padding
	 */
	void padPKCS7(unsigned char* const& buffer, const std::size_t bufferSize, const unsigned int startPos);

	std::size_t getSizeBeforePKCS7Padding(unsigned char* const& buffer, const std::size_t bufferSize);

	/**
	 * @brief Return number of AES rounds for given key size
	 *
	 * @param keySizeWords Size of AES key in words
	 * 
	 * @return AES rounds number
	 */
	std::size_t getNumbRounds(std::size_t keySizeWords);

    /**
	 * @brief Rotate word left by number of bits specified
	 * 
	 * @param words 32-bit word to rotate
	 * @param shiftAmount Number of bits to shift
	 */
	void rotateWordLeft(uint32_t& words, const std::size_t shiftAmount);

	/**
	 * @brief XORs each byte in buffer with corresponding byte in a key
	 * 
	 * @param buffer Pointer to data buffer for XOR
	 * @param key Pointer to key used for XOR
	 * @param keySizedBytes Number of bytes in key
	 */
	void xorByteArray(unsigned char* buffer, unsigned char* key, std::size_t keySizeBytes);

	/**
	 * @brief Peforms Galois mutiplication
	 * 
	 * @param value The byte to be multiplied
	 * @param multiplier The number to multiply by
	 * 
	 * @return Multiplication result
	 */
	unsigned char galoisMultiply(unsigned char value, unsigned char multiplier);

	/**
	 * @brief Mix columns in AES block 
	 * 
	 * @param buffer Data buffer in AES block
	 * @param size Buffer size
	 * @param rowCount Number of rows in AES block
	 */
	void mixColumns(unsigned char* buffer, const std::size_t size, const std::size_t rowCount);

	/**
	 * @brief Inverse Mix columns in AES block
	 *
	 * @param buffer Data buffer in AES block
	 * @param size Buffer size
	 * @param rowCount Number of rows in AES block
	 */
	void inverseMixColumns(unsigned char* buffer, const std::size_t size, const std::size_t rowCount);

	/**
	 * @brief Shift rows in AES block
	 * 
	 * @param buffer Data buffer in AES block
	 * @param size Buffer size
	 * @param rowCount Number of rows in AES block
	 */
	void shiftRows(unsigned char* buffer, const std::size_t size, const std::size_t rowCount);

	/**
	 * @brief Inverse Shift rows in AES block
	 *
	 * @param buffer Data buffer in AES block
	 * @param size Buffer size
	 * @param rowCount Number of rows in AES block
	 */
	void inverseShiftRows(unsigned char* buffer, const std::size_t size, const std::size_t rowCount);

	//void shiftCols(uint32_t* const& buffer, const std::size_t rowCount); UNUSED

	/** 
	 * @brief Performs S-box substitution on AES block
	 * 
	 * @param buffer Data buffer to perform substitution on
	 * @param bufferSize Size of buffer
	 */
	void sBoxSubstitution(unsigned char* const& buffer, const std::size_t bufferSize);

	/**
	 * @brief Performs Inverse S-box substitution on AES block
	 *
	 * @param buffer Data buffer to perform substitution on
	 * @param bufferSize Size of buffer
	 */
	void inverseSBoxSubstitution(unsigned char* const& buffer, const std::size_t bufferSize);

	/**
	 * @brief Prints buffer in row major order
	 * 
	 * @param buffer Data buffer to print
	 * @param size Size of buffer
	 * @param colCount Number of columns 
	 */
	void printBufferRowMajorOrder(const unsigned char* const& buffer, const std::size_t size, const std::size_t colCount);

	/**
	 * @brief Prints buffer in row major order
	 *
	 * @param buffer Data buffer to print
	 * @param size Size of buffer 
	 * @param colCount Number of columns
	 */
	void printBufferColMajorOrder(const unsigned char* const& buffer, const std::size_t size, const unsigned int colCount);

	/**
	 * @brief Compare two files
	 * 
	 * @param path1 Path to first file
	 * @param path2 Path to second file
	 * 
	 * @return True if files are identical, else false
	 */
	bool compareFiles(const std::string& path1, const std::string& path2);
}