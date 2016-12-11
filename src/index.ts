import { AES } from './aes';

// const key = '3daf0acbcae42e1f765a4efb52d92fc1ad305831bbf5770c6c7af8f50491b84f65e668158d060a196023b0041eea483a73170c70c954402e4acf2ce055ec796318c2771c36a789174b225c0f5eea80894c3835d49d0b3bc3e44c2b05e37a317f1e7d9bb556b00b80b51bf4210c100220b7200e0a2d40819a8506fcf0cfaf';
const key = AES.generateKey(256);
const cipherText = AES.encrypt('This is a super long message that needs to be encrypted by AES00', key, 256);
const plaintext = AES.decrypt(cipherText, key, 256);

console.log(plaintext);
