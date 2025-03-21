# Trình biên dịch
CC = g++
CFLAGS = -Wall -std=c++17

# Danh sách các file nguồn
SRCS = encryption.cpp decryption.cpp feistel.cpp file_io.cpp key_schedule.cpp permutation.cpp sbox.cpp utils.cpp

# Các file .o (object)
OBJS = $(SRCS:.cpp=.o)

# Tên file thực thi
CLIENT = client
SERVER = server
TEST_DES = test_des
TEST_ENC = encr_test
TEST_DEC = decr_test

# Mục tiêu mặc định khi chạy `make`
all: $(CLIENT) $(SERVER) $(TEST_DES) $(TEST_ENC) $(TEST_DEC)

# Biên dịch các file thư viện thành object (.o)
%.o: %.cpp
	$(CC) $(CFLAGS) -c $< -o $@

# Biên dịch Client
$(CLIENT): client.cpp $(OBJS)
	$(CC) $(CFLAGS) -o $(CLIENT) client.cpp $(OBJS)

# Biên dịch Server
$(SERVER): server.cpp $(OBJS)
	$(CC) $(CFLAGS) -o $(SERVER) server.cpp $(OBJS)

# Biên dịch file main.cpp để kiểm thử thuật toán DES
$(TEST_DES): main.cpp $(OBJS)
	$(CC) $(CFLAGS) -o $(TEST_DES) main.cpp $(OBJS)

$(TEST_ENC): encrypt_test.cpp $(OBJS)
	$(CC) $(CFLAGS) -o $(TEST_ENC) encrypt_test.cpp $(OBJS)

$(TEST_DEC): decrypt_test.cpp $(OBJS)
	$(CC) $(CFLAGS) -o $(TEST_DEC) decrypt_test.cpp $(OBJS)

# Lệnh dọn dẹp
clean:
	rm -f $(OBJS) $(CLIENT) $(SERVER) $(TEST_DES) $(TEST_ENC) $(TEST_DEC)

