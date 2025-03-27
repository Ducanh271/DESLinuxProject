#include "encryption.h"
#include "feistel.h"
#include "key_schedule.h"
#include "file_io.h"
#include "utils.h"
#include "thread_utils.h" // Include file chứa biến và hàm chung
#include <iostream>
#include <fstream>
#include <vector>
#include <thread>
#include <mutex>
#include <queue>
#include <condition_variable>

// Cấu hình
const size_t BLOCK_SIZE = 8;
const size_t MIN_SIZE_FOR_THREADS = 1024; // Ngưỡng kích thước file để dùng multi-threading (1KB)

// Hàm mã hóa đơn luồng (dùng cho file nhỏ)
void encryptSingleThread(std::ifstream& inputFile, std::ofstream& outputFile,
                         const std::vector<std::vector<uint8_t>>& subkeys) {
    std::vector<uint8_t> block(BLOCK_SIZE);
    while (inputFile.read(reinterpret_cast<char*>(block.data()), BLOCK_SIZE)) {
        std::vector<uint8_t> bitBlock = convertByteToBit(block);
        std::vector<uint8_t> encryptedBlock = desEncrypt(bitBlock, subkeys);
        std::vector<uint8_t> encryptedBytes = convertBitToByte(encryptedBlock);
        outputFile.write(reinterpret_cast<const char*>(encryptedBytes.data()), encryptedBytes.size());
    }

    // Xử lý padding cho phần còn lại
    size_t bytesRead = inputFile.gcount();
    if (bytesRead > 0) {
        block.resize(bytesRead);
        block = addPadding(block);
        std::vector<uint8_t> bitBlock = convertByteToBit(block);
        std::vector<uint8_t> encryptedBlock = desEncrypt(bitBlock, subkeys);
        std::vector<uint8_t> encryptedBytes = convertBitToByte(encryptedBlock);
        outputFile.write(reinterpret_cast<const char*>(encryptedBytes.data()), encryptedBytes.size());
    }
}

// Hàm chính
void encryptFile(const std::string& inputFilename, const std::string& outputFilename,
                 const std::vector<uint8_t>& key) {
    if (key.size() != 64) {
        std::cerr << "❌ Lỗi: Khóa DES phải có đúng 8 byte!" << std::endl;
        return;
    }

    std::ifstream inputFile(inputFilename, std::ios::binary);
    std::ofstream outputFile(outputFilename, std::ios::binary);
    if (!inputFile || !outputFile) {
        std::cerr << "❌ Lỗi: Không thể mở file!" << std::endl;
        return;
    }

    // Sinh khóa con
    std::vector<std::vector<uint8_t>> subkeys = generateSubkeys(key);

    // Kiểm tra kích thước file để quyết định dùng multi-threading hay không
    inputFile.seekg(0, std::ios::end);
    size_t fileSize = inputFile.tellg();
    inputFile.seekg(0, std::ios::beg);

    if (fileSize < MIN_SIZE_FOR_THREADS) {
        // File nhỏ: dùng đơn luồng
        encryptSingleThread(inputFile, outputFile, subkeys);
        std::cout << "✅ Đã mã hóa file thành công (đơn luồng): " << outputFilename << std::endl;
    } else {
        // File lớn: dùng multi-threading
        size_t numBlocks = (fileSize + BLOCK_SIZE - 1) / BLOCK_SIZE;
        unsigned int numThreads = std::thread::hardware_concurrency();
        if (numThreads == 0) numThreads = 4;

        // Cấp phát trước kết quả
        std::vector<std::vector<uint8_t>> results(numBlocks);
        size_t completedBlocks = 0;

        // Khởi tạo thread pool
        std::vector<std::thread> workers;
        for (unsigned int i = 0; i < numThreads; ++i) {
            workers.emplace_back(workerThread, std::cref(subkeys), std::ref(results), std::ref(completedBlocks), false); // false: mã hóa
        }

        // Đọc và đưa công việc vào queue
        std::vector<uint8_t> block(BLOCK_SIZE);
        size_t blockIndex = 0;
        while (inputFile.read(reinterpret_cast<char*>(block.data()), BLOCK_SIZE)) {
            {
                std::lock_guard<std::mutex> lock(queueMutex);
                taskQueue.emplace(blockIndex++, block);
            }
            queueCV.notify_one();
        }

        // Xử lý padding
        size_t bytesRead = inputFile.gcount();
        if (bytesRead > 0) {
            block.resize(bytesRead);
            block = addPadding(block);
            {
                std::lock_guard<std::mutex> lock(queueMutex);
                taskQueue.emplace(blockIndex++, block);
            }
            queueCV.notify_one();
        }

        // Đánh dấu hoàn tất
        {
            std::lock_guard<std::mutex> lock(queueMutex);
            done = true;
        }
        queueCV.notify_all();

        // Chờ các thread hoàn thành
        for (auto& worker : workers) {
            worker.join();
        }

        // Ghi kết quả
        for (const auto& result : results) {
            outputFile.write(reinterpret_cast<const char*>(result.data()), result.size());
        }

        std::cout << "✅ Đã mã hóa file thành công (đa luồng): " << outputFilename << std::endl;
    }

    inputFile.close();
    outputFile.close();
}
