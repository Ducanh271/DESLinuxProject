// thread_utils.cpp
#include "thread_utils.h"
#include "encryption.h"
#include "decryption.h"
#include "utils.h"
#include "feistel.h"
// Định nghĩa biến toàn cục
std::queue<std::pair<size_t, std::vector<uint8_t>>> taskQueue;
std::mutex queueMutex;
std::condition_variable queueCV;
std::mutex resultMutex;
bool done = false;

// Định nghĩa hàm workerThread
void workerThread(const std::vector<std::vector<uint8_t>>& subkeys,
                  std::vector<std::vector<uint8_t>>& results,
                  size_t& completedBlocks,
                  bool isDecrypt) {
    while (true) {
        std::pair<size_t, std::vector<uint8_t>> task;

        {
            std::unique_lock<std::mutex> lock(queueMutex);
            queueCV.wait(lock, [] { return !taskQueue.empty() || done; });
            if (done && taskQueue.empty()) break;

            task = taskQueue.front();
            taskQueue.pop();
        }

        // Xử lý mã hóa hoặc giải mã dựa trên isDecrypt
        std::vector<uint8_t> bitBlock = convertByteToBit(task.second);
        std::vector<uint8_t> processedBlock = isDecrypt ? desDecrypt(bitBlock, subkeys) : desEncrypt(bitBlock, subkeys);
        std::vector<uint8_t> processedBytes = convertBitToByte(processedBlock);

        // Lưu kết quả
        {
            std::lock_guard<std::mutex> lock(resultMutex);
            results[task.first] = processedBytes;
            ++completedBlocks;
        }
    }
}
