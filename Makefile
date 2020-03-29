CPPFLAGS := --std=c++14 -Wall -Wextra -pedantic

postlinker: postlinker.cpp relocations.o files.o
	g++ $(CPPFLAGS) -o $@ $^

relocations.o: relocations.cpp relocations.h
	g++ -c $(CPPFLAGS) -o $@ $<

files.o: files.cpp files.h
	g++ -c $(CPPFLAGS) -o $@ $<

clean:
	rm -f postlinker files.o relocations.o
