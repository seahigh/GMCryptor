{
  "targets": [
    {
      "include_dirs": [
        "<!(node -e \"require('nan')\")",
        "./include"
      ],
      "sources": ["addon.cc"],
       "conditions": [
        ['OS=="win"', {
          
        }],
        ['OS=="linux"', {
         
        }],
        ['OS=="mac"', {
          "conditions": [
              ['target_arch=="arm64"', {
                'target_name': 'gmCryptor-c-addon-darwin-arm64',
                'libraries': [ '../libcrypto-darwin-arm64.a' ]        
              }],
              ['target_arch=="x64"', {
                'target_name': 'gmCryptor-c-addon-darwin-x64',
                'libraries': [ '../libcrypto-darwin-x64.a' ] 
              }],
          ]
        }]
      ]
    }
  ]
}
