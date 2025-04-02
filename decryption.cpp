#include "decryption.h"
#include "feistel.h"
#include "key_schedule.h"
#include "file_io.h"
#include "utils.h"
#include "thread_utils.h"  // Thêm header mới
#include <iostream>
#include <thread>          // Thêm thư viện thread
#include <chrono>          // Để đo thời gian xử lý

void decryptFile(const std::string& inputFilename, const std::string& outputFilename, const std::vector<uint8_t>& key) {
    auto startTime = std::chrono::high_resolution_clock::now();
    
    // Chuẩn hóa khóa DES
    std::vector<uint8_t> desKey = normalizeDESKey(key);
    
    // Đọc file mã hóa
    std::vector<uint8_t> ciphertext = readFile(inputFilename);
    if (ciphertext.empty()) {
        std::cerr << "❌ Lỗi: File mã hóa trống hoặc không tồn tại!" << std::endl;
        return;
    }
    
    // Chuyển đổi khóa từ dạng byte sang bit
    std::vector<uint8_t> bitKey = convertByteToBit(desKey);
    
    // Sinh các khóa con
    std::vector<std::vector<uint8_t>> subkeys = generateSubkeys(bitKey);
    
    // Xác định số lượng khối và số lượng luồng
    size_t numBlocks = ciphertext.size() / 8;
    size_t numThreads = std::thread::hardware_concurrency();
    numThreads = std::min(numThreads, numBlocks); // Không tạo quá nhiều luồng
    numThreads = std::max(numThreads, (size_t)1); // Đảm bảo ít nhất 1 luồng
    
    std::cout << "🧵 Sử dụng " << numThreads << " luồng để giải mã " << numBlocks << " khối" << std::endl;

    // Chuẩn bị vector kết quả
    std::vector<std::vector<uint8_t>> results(numBlocks);
    size_t completedBlocks = 0;
    
    // Khởi tạo các luồng công việc
    std::vector<std::thread> threads;
    
    // Đảm bảo hàng đợi trống
    {
        std::lock_guard<std::mutex> lock(queueMutex);
        while (!taskQueue.empty()) {
            taskQueue.pop();
        }
        done = false;  // Reset biến done
    }
    
    // Khởi tạo các luồng xử lý
    for (size_t i = 0; i < numThreads; ++i) {
        threads.emplace_back(workerThread, std::ref(subkeys), std::ref(results), 
                            std::ref(completedBlocks), true);  // true cho giải mã
    }
    
    // Đẩy các khối dữ liệu vào hàng đợi
    for (size_t i = 0; i < numBlocks; ++i) {
        // Đảm bảo đủ 8 bytes cho mỗi khối
        std::vector<uint8_t> block;
        if (i * 8 + 8 <= ciphertext.size()) {
            block.assign(ciphertext.begin() + i * 8, ciphertext.begin() + (i + 1) * 8);
        } else {
            // Trường hợp khối cuối không đủ 8 bytes (hiếm gặp)
            block.assign(ciphertext.begin() + i * 8, ciphertext.end());
            block.resize(8, 0); // Thêm padding 0
        }
        
        {
            std::lock_guard<std::mutex> lock(queueMutex);
            taskQueue.push({i, block});
        }
        
        queueCV.notify_one();
    }
    
    // Chờ tất cả khối được xử lý
    while (true) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        
        std::lock_guard<std::mutex> lock(resultMutex);
        if (completedBlocks == numBlocks) break;
        
        // In tiến độ mỗi 10%
        if (numBlocks > 10 && completedBlocks % (numBlocks / 10) == 0) {
            std::cout << "⏳ Tiến độ giải mã: " << (completedBlocks * 100 / numBlocks) << "%" << std::endl;
        }
    }
    
    // Thông báo các luồng dừng lại
    {
        std::lock_guard<std::mutex> lock(queueMutex);
        done = true;
    }
    queueCV.notify_all();
    
    // Chờ các luồng kết thúc
    for (auto& t : threads) {
        t.join();
    }
    
    // Kết hợp kết quả
    std::vector<uint8_t> decryptedText;
    for (const auto& block : results) {
        decryptedText.insert(decryptedText.end(), block.begin(), block.end());
    }

    // Loại bỏ padding sau khi giải mã
    decryptedText = removePadding(decryptedText);

    // Ghi file giải mã
    writeFile(outputFilename, decryptedText);
    
    auto endTime = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
    
    std::cout << "✅ Đã giải mã file thành công: " << outputFilename << std::endl;
    std::cout << "⏱️ Thời gian giải mã: " << duration << " ms" << std::endl;
}
