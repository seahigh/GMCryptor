from ctypes import *
import ctypes
gmGo = cdll.LoadLibrary(
    '../release/gmCryptor-go-libs/gmCryptor-go-darwin-arm64.dylib')
testString = "{name: \"Seahigh DX\", nick: \"Seahigh DX\"}"
pubStr = "04efb77dc4e6545b0379901e3a8c656d0ef2623fd00ccab5afa8631f676715d679d89aa792f3b3a2bad5cfa0d30f30f1fb6e5e8ca11a0a3dcd714330a30f16e017"
priStr = "ac615b172f8bbc223de2f631d9c803e9a9b6dea9df81b1330d02fd9a874b44cf"

sm4KeyStr = "996ce17f6abc9fe126b57aa5f1d8c92c"
sm4IvStr = "504f1a1f80d40c760c74bd5257124dc9"

gmGo.sm3Hash.restype = c_char_p
print(gmGo.sm3Hash(c_char_p(testString.encode("utf-8"))).decode("utf-8"))
