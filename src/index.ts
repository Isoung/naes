import * as crypto from 'crypto';
import { AES } from './aes';

console.time('naes');
const naesKey = AES.generateKey(256);
const naesCipherText = AES.encrypt('This is a super long message that needs to be encrypted by AES00', naesKey, 256);
const naesPlaintext = AES.decrypt(naesCipherText, naesKey, 256);
console.timeEnd('naes');

console.time('crypto');
const cryptoCipher = crypto.createCipher('aes256', 'thisisareallylongkey');
const cryptoDecipher = crypto.createDecipher('aes256', 'thisisareallylongkey');

let cryptoEncrypted = cryptoCipher.update('This is a super long message that needs to be encrypted by AES00', 'utf8', 'hex');
cryptoEncrypted += cryptoCipher.final('hex');

let cryptoDecrypted = cryptoDecipher.update(cryptoEncrypted, 'hex', 'utf8');
cryptoDecrypted += cryptoDecipher.final('utf8');
console.timeEnd('crypto');

console.time('crypto-js');
import * as cryptojs from 'crypto-js';
const cjsCiphertext = cryptojs.AES.encrypt('This is a super long message that needs to be encrypted by AES00', 'thisisareallylongkey');
const cjsBytes = cryptojs.AES.decrypt(cjsCiphertext.toString(), 'thisisareallylongkey');
const cjsPlaintext = cjsBytes.toString(cryptojs.enc.Utf8);
console.timeEnd('crypto-js');
