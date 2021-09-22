# GMCryptor
SM2/SM3/SM4 Cryptor

GO、C(OpenSSL)、Rust等实现国密算法，供Node、JAVA、Lua(Openresty)调用

SM3、SM4[ECB]、SM4[CBC]、SM2[C1C3C2]、SM2[C1C2C3]、SM2[Asn1]、SM2 Sign&Verify

MacOS Intel/M1下测试通过，其他平台编译脚本完善ing

MacOS：

  brew install mingw-w64

  brew tap messense/macos-cross-toolchains

  brew install x86_64-unknown-linux-gnu

  brew install aarch64-unknown-linux-gnu

  brew install zstd
 
 
 CGO_ENABLED=1 GOARCH=amd64 GOOS=linux CC=x86_64-unknown-linux-gnu-gcc CXX=x86_64-unknown-linux-gnu-g++ go build -buildmode=c-shared -o GMCryptor-linux-x64.so GMCryptor.go GMCryptor_cgo.go && CGO_ENABLED=1 GOARCH=amd64 GOOS=windows CC=x86_64-w64-mingw32-gcc CXX=x86_64-w64-mingw32-g++ go build -buildmode=c-shared -o GMCryptor-windows-x64.dll GMCryptor.go GMCryptor_cgo.go && CGO_ENABLED=1 GOARCH=amd64 go build -buildmode=c-shared -o GMCryptor-darwin-x64.dylib GMCryptor.go GMCryptor_cgo.go && CGO_ENABLED=1 GOARCH=arm64 go build -buildmode=c-shared -o GMCryptor-darwin-arm64.dylib GMCryptor.go GMCryptor_cgo.go && CGO_ENABLED=0 GOOS=js GOARCH=wasm go build -o GMCryptor.wasm GMCryptor.go GMCryptor_wasm.go && CGO_ENABLED=1 GOARCH=amd64 go build -buildmode=c-archive -o GMCryptor-darwin-x64.a GMCryptor.go GMCryptor_cgo.go && CGO_ENABLED=1 GOARCH=arm64 go build -buildmode=c-archive -o GMCryptor-darwin-arm64.a GMCryptor.go GMCryptor_cgo.go && CGO_ENABLED=1 GOARCH=amd64 GOOS=windows CC=x86_64-w64-mingw32-gcc CXX=x86_64-w64-mingw32-g++ go build -buildmode=c-archive -o GMCryptor-windows-x64.a GMCryptor.go GMCryptor_cgo.go && cp GMCryptor-darwin-arm64.h GMCryptor.h && cd GMCryptorGoAddon && node-gyp configure --arch=x64 build && node-gyp configure --arch=arm64 build && cd .. && cd GMCryptorCAddon && node-gyp configure --arch=x64 build && node-gyp configure --arch=arm64 build & cd ..
