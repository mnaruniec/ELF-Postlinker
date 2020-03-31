Wystarczy skompilować program poleceniem make.
Rozwiązanie jest napisane w C++14, bez żadnych niestandardowych bibliotek, kompilowane g++.

Program oblicza miejsce potrzebne na nowe nagłówki ELF i programów, wyrównuje do maxa z rozmiaru strony i alignmentu segmentów i kopiuje plik exec do wynikowego z otrzymanym przesunięciem.
Na początku umieszcza nowe wersje nagłówków.
Segmenty stworzone na bazie pliku rel są dopisane na końcu pliku.
