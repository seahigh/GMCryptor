rm ../../release/gmCryptor-go-addon/*.node & rm -rf ./build/Release/ && node-gyp configure --arch=x64 build && node-gyp configure --arch=arm64 build && cp ./build/Release/*.node *.js ../../release/gmCryptor-go-addon/