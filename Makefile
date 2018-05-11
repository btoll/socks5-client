CC 		= gcc
FLAGS 	= -Wall -ggdb3
OUT 	= socks5_client

$(OUT): $(OUT).c $(OUT).h
	$(CC) $(FLAGS) -Wall -o socks5-client $(OUT).c $(OUT).h

