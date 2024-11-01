#include <cuda_runtime.h>
#include "device_launch_parameters.h"

#include "AES_GPU.cuh"
#include "AESFunctions.h"

__global__ void AES_GPU::encryptBlockAES_GPU(std::vector<unsigned char> buffer, std::vector<uint32_t> expandedKey, std::size_t numRounds, uint32_t* key, std::size_t keyWordSize) {
    int i = threadIdx.x;
    std::size_t offset = std::size_t(i) * AES_BLOCK_SIZE;

    aes::encryptBlockAES(buffer.data() + offset, expandedKey.data(), numRounds, key, keyWordSize);
}