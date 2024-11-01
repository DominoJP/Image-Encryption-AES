#pragma once
#include <cuda_runtime.h>
#include "device_launch_parameters.h"

#include <vector>

namespace AES_GPU {
	__global__ void encryptBlockAES_GPU(std::vector<unsigned char> buffer, std::vector<uint32_t> expandedKey, std::size_t numRounds, uint32_t* key, std::size_t keyWordSize);
}