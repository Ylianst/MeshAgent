# Makefile for MeshAgent Installation Assistant UI Test

CC = gcc
CFLAGS = -arch arm64 -mmacosx-version-min=11.0 -fobjc-arc -framework Cocoa -framework ApplicationServices

TARGET = install_ui_test
SOURCES = install_ui_test.m mac_install_window.m

all: $(TARGET)

$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCES)

clean:
	rm -f $(TARGET)

run: $(TARGET)
	./$(TARGET)

.PHONY: all clean run
