{
  'targets': [
    {
       'include_dirs': [
        "<!(node -e \"require('nan')\")"
      ],
      'sources': [
        'addon.cc'
      ],
      "conditions": [
         
        ['OS=="win"', {
          
        }],
        ['OS=="linux"', {
         
        }],
        ['OS=="mac"', {
          "conditions": [
              ['target_arch=="arm64"', {
                'target_name': 'gmCryptor-go-addon-darwin-arm64',
                'libraries': [ '../../../libs/gmCryptor-go-libs/gmCryptor-go-darwin-arm64.a' ]        
              }],
              ['target_arch=="x64"', {
                'target_name': 'gmCryptor-go-addon-darwin-x64',
                'libraries': [ '../../../libs/gmCryptor-go-libs/gmCryptor-go-darwin-x64.a' ] 
              }],
          ]
        }]
      ]
    }
  ]
}