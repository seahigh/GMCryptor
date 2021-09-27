clang -arch x86_64 -shared -fPIC -o ../../release/gmCryptor-c-libs/gmCryptor-c-darwin-x64.dylib gmCryptor-clib.cc libcrypto-darwin-x64.a -I ./include &&
clang -arch arm64 -shared -fPIC -o ../../release/gmCryptor-c-libs/gmCryptor-c-darwin-arm64.dylib gmCryptor-clib.cc libcrypto-darwin-arm64.a -I ./include

