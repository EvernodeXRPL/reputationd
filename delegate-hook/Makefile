.PHONY: all build

all: build upload

build:
	mkdir -p build
	wasmcc ./src/delegate.c -o ./build/delegate.wasm -O0 -Wl,--allow-undefined -I../
	wasm-opt -O2 ./build/delegate.wasm -o ./build/delegate.wasm
	hook-cleaner ./build/delegate.wasm

upload:
	node sethook.js

clean:
	rm -rf build/*