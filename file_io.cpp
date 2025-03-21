#include "file_io.h"
#include <fstream>
#include <iostream>

// Đọc nội dung file dưới dạng vector<uint8_t>
std::vector<uint8_t> readFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "❌ Lỗi: Không thể mở file " << filename << std::endl;
        return {};
    }

    std::vector<uint8_t> buffer((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();
    return buffer;
}

// Ghi dữ liệu vector<uint8_t> vào file
void writeFile(const std::string& filename, const std::vector<uint8_t>& data) {
    std::ofstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "❌ Lỗi: Không thể tạo file " << filename << std::endl;
        return;
    }

    file.write(reinterpret_cast<const char*>(data.data()), data.size());
    file.close();
}

