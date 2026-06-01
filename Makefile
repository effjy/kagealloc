CC = gcc
CFLAGS = -O2 -Wall -ffixed-r15
GTK_FLAGS = `pkg-config --cflags --libs gtk+-3.0`
TARGET_CLI = kagealloc_test
TARGET_GUI = kagealloc_gui

all: $(TARGET_CLI) $(TARGET_GUI)

$(TARGET_CLI): kagealloc.c main.c kagealloc.h
	$(CC) $(CFLAGS) kagealloc.c main.c -o $(TARGET_CLI)

$(TARGET_GUI): kagealloc.c gui.c kagealloc.h
	$(CC) $(CFLAGS) kagealloc.c gui.c -o $(TARGET_GUI) $(GTK_FLAGS)

CLI: $(TARGET_CLI)

GUI: $(TARGET_GUI)

clean:
	rm -f $(TARGET_CLI) $(TARGET_GUI)

run: all
	./$(TARGET_CLI)

run_gui: all
	./$(TARGET_GUI)
