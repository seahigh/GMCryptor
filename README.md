# GMCryptor
SM2/SM3/SM4 Cryptor

GO、C(OpenSSL)、Rust等实现国密算法，供Web、NodeJS、JAVA、Lua(Openresty)、iOS/Andriod调用

SM3、SM4[ECB]、SM4[CBC]、SM2[C1C3C2]、SM2[C1C2C3]、SM2[Asn1]、SM2 Sign&Verify

MacOS Intel/M1下测试通过，其他平台编译脚本完善ing

MacOS：

  brew install mingw-w64

  brew tap messense/macos-cross-toolchains

  brew install x86_64-unknown-linux-gnu

  brew install aarch64-unknown-linux-gnu

  brew install zstd
