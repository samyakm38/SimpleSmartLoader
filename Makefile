all:
	gcc  -m32 -no-pie -nostdlib -o sum sum.c
	gcc  -m32 -no-pie -nostdlib -o fib fib.c
	gcc -m32 -o SSL_withbonus SSL_withbonus.c
	gcc -m32 -o SSL SSL.c
	./SSL_withbonus sum

clean:
	-@rm -f sum SSL_withbonus
	