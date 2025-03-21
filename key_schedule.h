#ifndef KEY_SCHEDULE_H
#define KEY_SCHEDULE_H

#include <vector>
#include <cstdint>

std::vector<std::vector<uint8_t>> generateSubkeys(const std::vector<uint8_t>& key);
void leftShift(std::vector<uint8_t>& key, int shifts);

#endif // KEY_SCHEDULE_H

