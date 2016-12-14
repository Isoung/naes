# naes (Node AES)
# PURELY FOR EDUCATIONAL USES. SHOULD NOT BE USED IN PRODUCTION.
# Built using pseudocode 
* http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
* https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
* https://en.wikipedia.org/wiki/Rijndael_key_schedule
* https://en.wikipedia.org/wiki/Rijndael_mix_columns

### Built with Typescript which is compiled into Javascript

# Usage
```Typescript
  import * as { AES } from 'naes';
  
  const key = AES.generateKey(256) // keylength size
  const cipherText = AES.encrypt(message, key, keylength)
  const plainText = AES.decrypt(cipherText, key, keylength)
```

# Running index.js
* Install Node Version 7.2.0+
* Clone git repo
* Run commands
```shell
  npm install
  npm run build
  node ./dist/index.js
  
  # should ouput some benchmarking information
  # naes: 8.587ms
  # crypto: 0.960ms
  # crypto-js: 59.135ms
```
