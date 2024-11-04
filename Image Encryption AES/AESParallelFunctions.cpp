#include "AESParallelFunctions.h"
#include "AESFunctions.h"

#include <iostream>
#include <bitset>
#include <cassert>
#include <queue>
#include <omp.h>
#include <memory>
#include <stdio.h>


struct AESBlock
{
    std::streampos filePos = -1;
    std::size_t dataSize = 0;
    unsigned char buffer[AES_BLOCK_SIZE] = { 0 };
};

bool aes::encryptFilePC(std::ifstream& inFile, std::ofstream& outFile, uint32_t* key, std::size_t keyWordSize, std::size_t consumerCount)
{
    const int READ_THREAD = 0;
    const int WRITE_THREAD = 1;
    const int THREAD_COUNT = 2 + consumerCount;

    assert(inFile.is_open() && outFile.is_open());

    // Number of rounds, based on key size
    std::size_t numRounds = getNumbRounds(keyWordSize);

    // Allocate buffer for round keys
    // Number of 32-bit key words after expansion
    // equals 4 * (Nr + 1) according to FIPS 197
    std::vector<uint32_t> expandedKey = std::vector<uint32_t>((numRounds + 1) * 4, 0);

    // Generate keys for each round
    expandKey(expandedKey.data(), numRounds, key, keyWordSize);

    bool doneReading = false;

    std::queue<std::shared_ptr<AESBlock>> inputQueue = std::queue<std::shared_ptr<AESBlock>>();
    std::queue<std::shared_ptr<AESBlock>> outputQueue = std::queue<std::shared_ptr<AESBlock>>();

    inFile.seekg(0, inFile.end);
    const std::streampos fileSize = inFile.tellg();
    inFile.seekg(0, inFile.beg);

    std::streampos finalFileSize = fileSize;
    if (fileSize % AES_BLOCK_SIZE == 0)
        finalFileSize += AES_BLOCK_SIZE;
    else
        finalFileSize += AES_BLOCK_SIZE - (fileSize % AES_BLOCK_SIZE);

    outFile.seekp(finalFileSize - (std::streampos)1);
    outFile.write("", 1);
    outFile.seekp(0, outFile.beg);

    const int writeTotal = finalFileSize / 16;

    //std::cout << std::dec << "Write Total: " << writeTotal << std::endl;

#   pragma omp parallel num_threads(THREAD_COUNT) default(none) shared(std::cout, expandedKey, numRounds, key, keyWordSize, inputQueue, outputQueue, writeTotal, doneReading, inFile, outFile, fileSize, READ_THREAD, WRITE_THREAD)
    {
        int threadRank = omp_get_thread_num();
        if (threadRank == READ_THREAD) {
            while (!inFile.eof()) {
                std::shared_ptr<AESBlock> blockPtr = std::make_shared<AESBlock>();

                blockPtr->filePos = inFile.tellg();
                inFile.read(reinterpret_cast<char*>(blockPtr->buffer), AES_BLOCK_SIZE);
                blockPtr->dataSize = inFile.gcount();

                //std::cout << "Read Block: " << blockPtr->filePos << std::endl;

#               pragma omp critical(INPUTACCESS)
                inputQueue.push(blockPtr);
            }

            if (fileSize % AES_BLOCK_SIZE == 0) {
                std::shared_ptr<AESBlock> blockPtr = std::make_shared<AESBlock>();
                blockPtr->filePos = fileSize;
                blockPtr->dataSize = 0;

#               pragma omp critical(INPUTACCESS)
                inputQueue.push(blockPtr);
            }

#           pragma omp critical(READINGBOOL)
            doneReading = true;

            //std::cout << "Reading Thread Finished\n";
        }
        else if (threadRank == WRITE_THREAD)
        {
            int writeCount = 0;
            while (writeCount < writeTotal) {
                std::shared_ptr<AESBlock> blockPtr = nullptr;

#               pragma omp critical(OUTPUTACCESS)
                {
                    if (!outputQueue.empty()) {
                        blockPtr = outputQueue.front();
                        outputQueue.pop();
                    }
                }

                if (blockPtr != nullptr) {
                    //std::cout << "Writing Block: " << blockPtr->filePos << std::endl;
                    outFile.seekp(blockPtr->filePos);
                    outFile.write(reinterpret_cast<char*>(blockPtr->buffer), AES_BLOCK_SIZE);

                    writeCount++;
                }
            }

            //std::cout << "Writing Thread Finished\n";
        }
        else {
            bool isEmpty = true;
#           pragma omp critical(INPUTACCESS)
            isEmpty = inputQueue.empty();

            while (!doneReading || !isEmpty) {//writeCount < writeTotal) {//(!done || !empty) {
                std::shared_ptr<AESBlock> blockPtr = nullptr;

#               pragma omp critical(INPUTACCESS)
                {
                    if (!inputQueue.empty()) {
                        blockPtr = inputQueue.front();
                        inputQueue.pop();
                        isEmpty = inputQueue.empty();
                    }
                    else
                        isEmpty = true;
                }

                if (blockPtr != nullptr) {
                    //std::cout << "Encrypting Block: " << blockPtr->filePos << std::endl;
                    // If the block is less than 128-bits pad it.
                    if (blockPtr->dataSize < AES_BLOCK_SIZE)
                        aes::padPKCS7(blockPtr->buffer, AES_BLOCK_SIZE, blockPtr->dataSize);

                    // AES Encryption
                    encryptBlockAES(blockPtr->buffer, expandedKey.data(), numRounds, key, keyWordSize);

#                   pragma omp critical(OUTPUTACCESS)
                    outputQueue.push(blockPtr);
                }
            }
            //std::cout << "Encryption Thread Finished\n";
        }
    }

    return true;
}

/*
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
*/

bool aes::encryptFilePC2(std::ifstream& inFile, std::ofstream& outFile, uint32_t* key, std::size_t keyWordSize, std::size_t consumerCount, std::size_t jobSize)
{
    const int JOB_SIZE = jobSize;
    const int READ_THREAD = 0;
    const int WRITE_THREAD = 1;
    const int THREAD_COUNT = 2 + consumerCount;

    assert(inFile.is_open() && outFile.is_open());

    // Number of rounds, based on key size
    std::size_t numRounds = getNumbRounds(keyWordSize);

    // Allocate buffer for round keys
    // Number of 32-bit key words after expansion
    // equals 4 * (Nr + 1) according to FIPS 197
    std::vector<uint32_t> expandedKey = std::vector<uint32_t>((numRounds + 1) * 4, 0);

    // Generate keys for each round
    expandKey(expandedKey.data(), numRounds, key, keyWordSize);

    bool doneReading = false;

    std::queue<std::shared_ptr<std::vector<AESBlock>>> inputQueue = std::queue<std::shared_ptr<std::vector<AESBlock>>>();
    std::queue<std::shared_ptr<std::vector<AESBlock>>> outputQueue = std::queue<std::shared_ptr<std::vector<AESBlock>>>();

    inFile.seekg(0, inFile.end);
    const std::streampos fileSize = inFile.tellg();
    inFile.seekg(0, inFile.beg);

    std::streampos finalFileSize = fileSize;
    if (fileSize % AES_BLOCK_SIZE == 0)
        finalFileSize += AES_BLOCK_SIZE;
    else
        finalFileSize += AES_BLOCK_SIZE - (fileSize % AES_BLOCK_SIZE);

    assert(finalFileSize > 0);

    outFile.seekp(finalFileSize - (std::streampos)1);
    outFile.write("", 1);
    outFile.seekp(0, outFile.beg);

    const int writeTotal = finalFileSize / AES_BLOCK_SIZE;

    //std::cout << std::dec << "Write Total: " << writeTotal << std::endl;

#   pragma omp parallel num_threads(THREAD_COUNT) default(none) shared(std::cout, expandedKey, numRounds, key, keyWordSize, inputQueue, outputQueue, writeTotal, doneReading, inFile, outFile, fileSize, READ_THREAD, WRITE_THREAD)
    {
        int threadRank = omp_get_thread_num();
        if (threadRank == READ_THREAD) {
            while (!inFile.eof()) {
                std::shared_ptr<std::vector<AESBlock>> tasks = std::make_shared<std::vector<AESBlock>>();
                tasks->reserve(JOB_SIZE);

                for (int i = 0; i < JOB_SIZE && !inFile.eof(); ++i) {
                    AESBlock block;
                    block.filePos = inFile.tellg();
                    inFile.read(reinterpret_cast<char*>(block.buffer), AES_BLOCK_SIZE);
                    block.dataSize = inFile.gcount();
                    tasks->push_back(block);
                }
                //std::cout << "Read Block: " << blockPtr->filePos << std::endl;

#               pragma omp critical(INPUTACCESS)
                inputQueue.push(tasks);
            }

            if (fileSize % AES_BLOCK_SIZE == 0) {
                std::shared_ptr<std::vector<AESBlock>> tasks = std::make_shared<std::vector<AESBlock>>();
                AESBlock block;
                block.filePos = fileSize;
                block.dataSize = 0;
                tasks->push_back(block);

#               pragma omp critical(INPUTACCESS)
                inputQueue.push(tasks);
            }

#           pragma omp critical(READINGBOOL)
            doneReading = true;

            //std::cout << "Reading Thread Finished\n";
        }
        else if (threadRank == WRITE_THREAD)
        {
            int writeCount = 0;
            while (writeCount < writeTotal) {
                std::shared_ptr<std::vector<AESBlock>> tasks = nullptr;

#               pragma omp critical(OUTPUTACCESS)
                {
                    if (!outputQueue.empty()) {
                        tasks = outputQueue.front();
                        outputQueue.pop();
                    }
                }

                if (tasks != nullptr) {
                    std::vector<AESBlock>::iterator it;
                    for (it = tasks->begin(); it != tasks->end(); ++it) {
                        outFile.seekp(it->filePos);
                        outFile.write(reinterpret_cast<char*>(it->buffer), AES_BLOCK_SIZE);

                        writeCount++;
                    }
                    //std::cout << "Writing Block: " << blockPtr->filePos << std::endl;
                }
            }

            //std::cout << "Writing Thread Finished\n";
        }
        else {
            bool isEmpty = true;
#           pragma omp critical(INPUTACCESS)
            isEmpty = inputQueue.empty();

            while (!doneReading || !isEmpty) {//writeCount < writeTotal) {//(!done || !empty) {
                std::shared_ptr<std::vector<AESBlock>> tasks = nullptr;

#               pragma omp critical(INPUTACCESS)
                {
                    if (!inputQueue.empty()) {
                        tasks = inputQueue.front();
                        inputQueue.pop();
                        isEmpty = inputQueue.empty();
                    }
                    else
                        isEmpty = true;
                }

                if (tasks != nullptr) {
                    std::vector<AESBlock>::iterator it;
                    for (it = tasks->begin(); it != tasks->end(); ++it) {
                        if(it->dataSize < AES_BLOCK_SIZE)
                            aes::padPKCS7(it->buffer, AES_BLOCK_SIZE, it->dataSize);

                        encryptBlockAES(it->buffer, expandedKey.data(), numRounds, key, keyWordSize);
                    }

#                   pragma omp critical(OUTPUTACCESS)
                    outputQueue.push(tasks);
                }
            }
            //std::cout << "Encryption Thread Finished\n";
        }
    }

    return true;
}