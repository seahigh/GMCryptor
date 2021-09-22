{
  'targets': [
    {
       'include_dirs': [
        "<!(node -e \"require('nan')\")"
      ],
      'sources': [
        'GMCryptorGoAddon.cc'
      ],
      "conditions": [
         
        ['OS=="win"', {
          
        }],
        ['OS=="linux"', {
         
        }],
        ['OS=="mac"', {
          "conditions": [
              ['target_arch=="arm64"', {
                'target_name': 'GMCryptorGoAddon-darwin-arm64',
                'libraries': [ '../../GMCryptor-darwin-arm64.a' ]        
              }],
              ['target_arch=="x64"', {
                'target_name': 'GMCryptorGoAddon-darwin-x64',
                'libraries': [ '../../GMCryptor-darwin-x64.a' ] 
              }],
          ]
        }]
      ]
    }
  ]
}