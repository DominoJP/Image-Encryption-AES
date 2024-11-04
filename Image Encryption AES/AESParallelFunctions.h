#pragma once
#include <stdint.h>
#include <vector>
#include <fstream>

namespace aes
{
	// Encrypt a file using a producer/consumer implementation
	bool encryptFilePC(std::ifstream& inFile, std::ofstream& outFile, uint32_t* key, std::size_t keyWordSize, std::size_t consumerCount);

	bool encryptFilePC2(std::ifstream& inFile, std::ofstream& outFile, uint32_t* key, std::size_t keyWordSize, std::size_t consumerCount, std::size_t jobSize = 400);

	//bool compareFiles(const std::string& path1, const std::string& path2);
}