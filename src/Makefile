CPPFLAGS=-I/opt/openssl1/include -L/opt/openssl1/lib

TARGET=arm
ifeq ($(TARGET), arm)
  # Use make TARGET=arm to compile for the Raspberry Pi
  CXX=arm-linux-gnueabihf-g++-14
  CPPFLAGS=-I/opt/arm/openssl/include -L/opt/arm/openssl/lib
endif

all: efergy.cc
	mkdir -p build
	$(CXX) -s -std=c++17 $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -Wall -o build/efergy $^ $(LDLIBS) -static -lcrypto -lssl -lcrypto -static-libgcc -static-libstdc++

clean:
	rm -rf build/efergy
