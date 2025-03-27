// thread_utils.h
#ifndef THREAD_UTILS_H
#define THREAD_UTILS_H

#include <queue>
#include <mutex>
#include <condition_variable>
#include <vector>

// Khai báo biến toàn cục với extern
extern std::queue<std::pair<size_t, std::vector<uint8_t>>> taskQueue;
extern std::mutex queueMutex;
extern std::condition_variable queueCV;
extern std::mutex resultMutex;
extern bool done;

// Khai báo hàm workerThread
void workerThread(const std::vector<std::vector<uint8_t>>& subkeys,
                  std::vector<std::vector<uint8_t>>& results,
                  size_t& completedBlocks,
                  bool isDecrypt = false); // Tham số isDecrypt để phân biệt mã hóa/giải mã

#endif // THREAD_UTILS_H
