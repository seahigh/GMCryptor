./emsdk install latest
./emsdk activate latest
source ./emsdk_env.sh

emconfigure ./Configure  darwin64-x86_64-cc -no-asm --api=1.1.0

CROSS_COMPILE=xxxxxxxx ---> CROSS_COMPILE=
CNF_CFLAGS=-arch x86_64 --->  CNF_CFLAGS=
 
emmake make -j 12 build_generated libssl.a libcrypto.a

emcc GMCryptorCWasm.c libcrypto.a libssl.a -I ./include -s EXPORTED_RUNTIME_METHODS='["cwrap", "ccall"]' -o GMCryptorCWasm.js