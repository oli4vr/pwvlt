all:
	gcc -c sha512.c -o sha512.o -O3
	gcc -c encrypt.c -o encrypt.o -O3
	gcc -c entropy.c -o entropy.o -O3
	gcc main.c -o pwvlt -O3 sha512.o encrypt.o entropy.o
clean:
	rm -rf *.o entrof pwvlt
install:
	mkdir -p ~/bin
	cp pwvlt ~/bin
uninstall:
	rm ~/bin/pwvlt

