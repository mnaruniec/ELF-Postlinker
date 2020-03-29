CPPFLAGS := --std=c++14 -Wall -Wextra -pedantic

postlinker: postlinker.cpp files.o
	g++ $(CPPFLAGS) -o $@ $^

files.o: files.cpp files.h
	g++ -c $(CPPFLAGS) -o $@ $<

clean:
	rm -f postlinker files.o
