#include "decryption.h"
#include "feistel.h"
#include "key_schedule.h"
#include "file_io.h"
#include "utils.h"
#include "thread_utils.h"
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

// Hàm giải mã đơn luồng (dùng cho file nhỏ)
void decryptSingleThread(std::ifstream& inputFile, std::ofstream& outputFile,
                         const std::vector<std::vector<uint8_t>>& subkeys) {
    std::vector<uint8_t> block(BLOCK_SIZE);
    std::vector<uint8_t> decryptedText;

    while (inputFile.read(reinterpret_cast<char*>(block.data()), BLOCK_SIZE)) {
        std::vector<uint8_t> bitBlock = convertByteToBit(block);
        std::vector<uint8_t> decryptedBlock = desDecrypt(bitBlock, subkeys);
        std::vector<uint8_t> decryptedBytes = convertBitToByte(decryptedBlock);
        decryptedText.insert(decryptedText.end(), decryptedBytes.begin(), decryptedBytes.end());
    }

    // Xử lý phần còn lại (nếu có)
    size_t bytesRead = inputFile.gcount();
    if (bytesRead > 0) {
        block.resize(bytesRead);
        std::vector<uint8_t> bitBlock = convertByteToBit(block);
        std::vector<uint8_t> decryptedBlock = desDecrypt(bitBlock, subkeys);
        std::vector<uint8_t> decryptedBytes = convertBitToByte(decryptedBlock);
        decryptedText.insert(decryptedText.end(), decryptedBytes.begin(), decryptedBytes.end());
    }

    // Loại bỏ padding và ghi file
    decryptedText = removePadding(decryptedText);
    outputFile.write(reinterpret_cast<const char*>(decryptedText.data()), decryptedText.size());
}

// Hàm chính
void decryptFile(const std::string& inputFilename, const std::string& outputFilename,
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

    // Kiểm tra kích thước file
    inputFile.seekg(0, std::ios::end);
    size_t fileSize = inputFile.tellg();
    inputFile.seekg(0, std::ios::beg);

    if (fileSize < MIN_SIZE_FOR_THREADS) {
        // File nhỏ: dùng đơn luồng
        decryptSingleThread(inputFile, outputFile, subkeys);
        std::cout << "✅ Đã giải mã file thành công (đơn luồng): " << outputFilename << std::endl;
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
            workers.emplace_back(workerThread, std::cref(subkeys), std::ref(results), 
                                 std::ref(completedBlocks), true); // true: giải mã
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

        // Xử lý phần còn lại (nếu có)
        size_t bytesRead = inputFile.gcount();
        if (bytesRead > 0) {
            block.resize(bytesRead);
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

        // Ghi kết quả và loại bỏ padding
        std::vector<uint8_t> decryptedText;
        for (const auto& result : results) {
            decryptedText.insert(decryptedText.end(), result.begin(), result.end());
        }
        decryptedText = removePadding(decryptedText);
        outputFile.write(reinterpret_cast<const char*>(decryptedText.data()), decryptedText.size());

        std::cout << "✅ Đã giải mã file thành công (đa luồng): " << outputFilename << std::endl;
    }

    inputFile.close();
    outputFile.close();
}
