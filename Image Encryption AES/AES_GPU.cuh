#pragma once
#include <cuda_runtime.h>
#include "device_launch_parameters.h"

#include <vector>

namespace AES_GPU {
	__global__ void encryptChunkAES_GPU(unsigned char* chunk, uint32_t* expandedKey, size_t numRounds, uint32_t* key, size_t keyWordSize);
	__device__ void encryptBlockAES_GPU(unsigned char* buffer, uint32_t* expandedKeys, const std::size_t numRounds, const uint32_t* const key, const std::size_t keySizeWords);
	__device__ void sBoxSubstitution_GPU(unsigned char* const& buffer, const std::size_t bufferSize);
	__device__ void shiftRows_GPU(unsigned char* buffer, const std::size_t size, const std::size_t rowCount);
	__device__ void mixColumns_GPU(unsigned char* buffer, const std::size_t size, const std::size_t rowCount);
	__device__ void xorByteArray_GPU(unsigned char* buffer, unsigned char* key, std::size_t keySizeBytes);
	__device__ unsigned char galoisMultiplyBy2(unsigned char value);
}