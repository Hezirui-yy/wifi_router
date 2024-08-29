CC=$(CROSS_COMPILE)gcc
CFLAGS=-Wall -I$(STAGING_DIR)/usr/include/json-c
LDFLAGS=-L$(STAGING_DIR)/usr/lib -ljson-c

# 目标文件名和源文件
TARGET=handle_request
SRCS=handle_request.c
OBJS=$(SRCS:.c=.o)

# 默认目标
all: $(TARGET)

# 生成目标文件
$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

# 生成对象文件
%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@

# 清理生成的文件
clean:
	rm -f $(OBJS) $(TARGET)

# 安装目标（可选）
install: $(TARGET)
	cp $(TARGET) /usr/local/bin/$(TARGET)

# 卸载目标（可选）
uninstall:
	rm -f /usr/local/bin/$(TARGET)

# 伪目标
.PHONY: all clean install uninstall
