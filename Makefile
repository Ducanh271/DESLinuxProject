# Trình biên dịch
CC = g++
CFLAGS = -Wall -std=c++17 -pthread -Wno-deprecated-declarations
GTK_CFLAGS = $(shell pkg-config --cflags gtk+-3.0)
GTK_LIBS = $(shell pkg-config --libs gtk+-3.0)
GMP_LIBS = -lgmp
SSL_LIBS = -lssl -lcrypto  # Thêm thư viện OpenSSL

# Danh sách các file nguồn
SRCS = encryption.cpp decryption.cpp feistel.cpp file_io.cpp key_schedule.cpp \
       permutation.cpp sbox.cpp utils.cpp rsa_core.cpp thread_utils.cpp

# Các file .o (object)
OBJS = $(SRCS:.cpp=.o)

# Tên file thực thi
CLIENT_GUI = client_gui
SERVER_GUI = server_gui
TEST_DES = test_des
TEST_ENC = encr_test
TEST_DEC = decr_test
KEY_GEN = rsa_key_generator

# Thư mục lưu trữ
DIRS = received_files decrypted_files

# Mục tiêu mặc định
all: directories $(CLIENT_GUI) $(SERVER_GUI) $(TEST_DES) $(TEST_ENC) $(TEST_DEC) $(KEY_GEN)

# Tạo các thư mục cần thiết
directories:
	mkdir -p $(DIRS)

# Biên dịch các file thư viện thành object (.o)
%.o: %.cpp
	$(CC) $(CFLAGS) -c $< -o $@

# Biên dịch Client với giao diện GTK
$(CLIENT_GUI): client_gui.cpp $(OBJS)
	$(CC) $(CFLAGS) $(GTK_CFLAGS) -o $@ client_gui.cpp $(OBJS) $(GTK_LIBS) $(GMP_LIBS) $(SSL_LIBS)

# Biên dịch Server với giao diện GTK
$(SERVER_GUI): server_gui.cpp $(OBJS)
	$(CC) $(CFLAGS) $(GTK_CFLAGS) -o $@ server_gui.cpp $(OBJS) $(GTK_LIBS) $(GMP_LIBS) $(SSL_LIBS)

# Biên dịch kiểm thử thuật toán DES
$(TEST_DES): main.cpp $(OBJS)
	$(CC) $(CFLAGS) -o $@ main.cpp $(OBJS) $(GMP_LIBS)

# Biên dịch kiểm thử mã hóa
$(TEST_ENC): encrypt_test.cpp $(OBJS)
	$(CC) $(CFLAGS) -o $@ encrypt_test.cpp $(OBJS) $(GMP_LIBS)

# Biên dịch kiểm thử giải mã
$(TEST_DEC): decrypt_test.cpp $(OBJS)
	$(CC) $(CFLAGS) -o $@ decrypt_test.cpp $(OBJS) $(GMP_LIBS)

# Biên dịch công cụ tạo khóa RSA
$(KEY_GEN): rsa_key_generator.cpp rsa_core.o
	$(CC) $(CFLAGS) -o $@ rsa_key_generator.cpp rsa_core.o $(GMP_LIBS)

# Dọn dẹp
clean:
	rm -f $(OBJS) $(CLIENT_GUI) $(SERVER_GUI) $(TEST_DES) $(TEST_ENC) $(TEST_DEC) $(KEY_GEN)
	rm -f *.key

# Dọn dẹp hoàn toàn (bao gồm cả file đã nhận và giải mã)
distclean: clean
	rm -rf $(DIRS)

.PHONY: all clean distclean directories

