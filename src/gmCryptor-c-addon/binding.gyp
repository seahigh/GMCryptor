{
  "targets": [
    {
      "include_dirs": [
        "<!(node -e \"require('nan')\")",
        "../gmCryptor-c-base/include"
      ],
      "sources": ["gmCryptor-c-addon.cc"],
       "conditions": [
        ['OS=="win"', {
          
        }],
        ['OS=="linux"', {
           "conditions": [
              ['target_arch=="x64"', {
                'target_name': 'gmCryptor-c-addon-linux-x64',
                'libraries': [ '../../gmCryptor-c-base/libcrypto-linux-x64.a' ] 
              }],
          ]         
        }],
        ['OS=="mac"', {
          "conditions": [
              ['target_arch=="arm64"', {
                'target_name': 'gmCryptor-c-addon-darwin-arm64',
                'libraries': [ '../../gmCryptor-c-base/libcrypto-darwin-arm64.a' ]        
              }],
              ['target_arch=="x64"', {
                'target_name': 'gmCryptor-c-addon-darwin-x64',
                'libraries': [ '../../gmCryptor-c-base/libcrypto-darwin-x64.a' ] 
              }],
          ]
        }]
      ]
    }
  ]
}
