CC 		= gcc
FLAGS 	= -W -Wall
TARGET 	= socks5_client
PREFIX	= /usr

.PHONY: build clean install

$(TARGET): $(TARGET).c $(TARGET).h
	$(CC) $(FLAGS) -Wall -o socks5-client $(TARGET).c $(TARGET).h

build: $(TARGET)

clean:
	rm -f $(TARGET) *.o

# https://www.gnu.org/software/make/manual/html_node/DESTDIR.html
install:
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	install -m 0755 socks5-client $(DESTDIR)$(PREFIX)/bin/

