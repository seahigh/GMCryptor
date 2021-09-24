安装 Emscripten:
./emsdk install latest
./emsdk activate latest
source ./emsdk_env.sh

编译OPENSSL:
emconfigure ./Configure  darwin64-x86_64-cc -no-asm --api=1.1.0

CROSS_COMPILE=xxxxxxxx ---> CROSS_COMPILE=
CNF_CFLAGS=-arch x86_64 --->  CNF_CFLAGS=
emmake make -j 12 build_generated libssl.a libcrypto.a

编译Botan:
CXX=em++ ./configure.py --cc=clang --cpu=llvm --os=emscripten
make

编译:
sh build.sh

OPENSSL的SM2无法正常通过Emscripten编译运行，估换Botan来实现，待完成...