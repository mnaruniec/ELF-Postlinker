CPPFLAGS := --std=c++14 -Wall -Wextra -pedantic

postlinker: postlinker.cpp
	g++ $(CPPFLAGS) -o $@ $<

clean:
	rm -f postlinker
