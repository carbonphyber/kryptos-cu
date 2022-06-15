run:
	./build/kryptos

compile: src/kryptos.cu
	nvcc -o ./build/kryptos src/kryptos.cu

clean:
	rm -f ./build/kryptos
