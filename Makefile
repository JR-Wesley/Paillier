all: build run

# link lib mp, m
build:
	g++ encry.cpp -o encry -g -O2 -std=c++11 -pthread -lntl -lgmp -lm

build_test:
	g++ test.cpp -o test -g -O2 -std=c++11 -pthread -lntl -lgmp -lm

# run 
run:
	./encry |tee -i run.log

# mm
build_mm:
	g++ -std=c++17 -O3 mm.cpp -o mm

clean:
	rm ./data/* ./encry ./run.log
	