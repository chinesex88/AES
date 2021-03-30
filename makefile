all:AES.cpp
	g++ AES.cpp -o AES
	./AES
clean:
	rm *.o AES
run:
	./AES