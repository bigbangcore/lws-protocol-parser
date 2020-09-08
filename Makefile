all:
	mkdir -p build && cd build && cmake .. && make && sudo make install

deps:
	git submodule init
	git submodule update