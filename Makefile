# Trình biên dịch
CC = g++
CFLAGS = -Wall -std=c++17 -pthread
GTK_CFLAGS = $(shell pkg-config --cflags gtk+-3.0)
GTK_LIBS = $(shell pkg-config --libs gtk+-3.0)

# Danh sách các file nguồn
SRCS = encryption.cpp decryption.cpp feistel.cpp file_io.cpp key_schedule.cpp permutation.cpp sbox.cpp utils.cpp thread_utils.cpp

# Các file .o (object)
OBJS = $(SRCS:.cpp=.o)

# Tên file thực thi
CLIENT = client
SERVER = server
CLIENT_GUI = client_gui
SERVER_GUI = server_gui
TEST_DES = test_des
TEST_ENC = encr_test
TEST_DEC = decr_test

# Mục tiêu mặc định
all: $(CLIENT) $(SERVER) $(TEST_DES) $(TEST_ENC) $(TEST_DEC) $(CLIENT_GUI) $(SERVER_GUI)

# Biên dịch các file thư viện thành object (.o)
%.o: %.cpp
	$(CC) $(CFLAGS) -c $< -o $@

# Biên dịch Client
$(CLIENT): client.cpp $(OBJS)
	$(CC) $(CFLAGS) -o $@ client.cpp $(OBJS)

# Biên dịch Server
$(SERVER): server.cpp $(OBJS)
	$(CC) $(CFLAGS) -o $@ server.cpp $(OBJS)

# Biên dịch Client với giao diện GTK
$(CLIENT_GUI): client_gui.cpp $(OBJS)
	$(CC) $(CFLAGS) $(GTK_CFLAGS) -o $@ client_gui.cpp $(OBJS) $(GTK_LIBS)

# Biên dịch Server với giao diện GTK
$(SERVER_GUI): server_gui.cpp $(OBJS)
	$(CC) $(CFLAGS) $(GTK_CFLAGS) -o $@ server_gui.cpp $(OBJS) $(GTK_LIBS)

# Biên dịch kiểm thử thuật toán DES
$(TEST_DES): main.cpp $(OBJS)
	$(CC) $(CFLAGS) -o $@ main.cpp $(OBJS)

$(TEST_ENC): encrypt_test.cpp $(OBJS)
	$(CC) $(CFLAGS) -o $@ encrypt_test.cpp $(OBJS)

$(TEST_DEC): decrypt_test.cpp $(OBJS)
	$(CC) $(CFLAGS) -o $@ decrypt_test.cpp $(OBJS)

# Dọn dẹp
clean:
	rm -f $(OBJS) $(CLIENT) $(SERVER) $(TEST_DES) $(TEST_ENC) $(TEST_DEC) $(CLIENT_GUI) $(SERVER_GUI)

.PHONY: all clean

