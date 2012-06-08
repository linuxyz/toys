
%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)


tunet: main.o
	$(CC) $(CFLAGS) -o tunet main.o


