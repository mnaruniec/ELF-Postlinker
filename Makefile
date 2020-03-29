CPPFLAGS := --std=c++14 -Wall -Wextra -pedantic

postlinker: postlinker.cpp structuring.o relocations.o types.o files.o
	g++ $(CPPFLAGS) -o $@ $^

structuring.o: structuring.cpp structuring.h types.h files.h constants.h
	g++ -c $(CPPFLAGS) -o $@ $<

relocations.o: relocations.cpp relocations.h types.h files.h constants.h
	g++ -c $(CPPFLAGS) -o $@ $<

types.o: types.cpp types.h constants.h
	g++ -c $(CPPFLAGS) -o $@ $<

files.o: files.cpp files.h constants.h
	g++ -c $(CPPFLAGS) -o $@ $<

clean:
	rm -f postlinker structuring.o relocations.o types.o files.o
