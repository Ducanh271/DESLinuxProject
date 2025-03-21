#ifndef FILE_IO_H
#define FILE_IO_H
#include <stdint.h>
#include <iostream>
#include <vector>
#include <fstream>


// Đọc nội dung file dưới dạng vector<uint8_t>
std::vector<uint8_t> readFile(const std::string& filename);

// Ghi dữ liệu vector<uint8_t> vào file
void writeFile(const std::string& filename, const std::vector<uint8_t>& data);

#endif // FILE_IO_H

