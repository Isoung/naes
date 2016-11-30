import { Boxes } from '.';
import xor = require('bitwise-xor');

export class AESCore {
  public static subBytes() {

  }

  public static shiftRows() {

  }

  public static mixColumns() {

  }

  public static addRoundKeys() {

  }

  // https://en.wikipedia.org/wiki/Rijndael_key_schedule#Key_schedule_core
  public static _keyExpansionCore(buffer: Buffer, rconValue: number): Buffer {
    const returnValue = Buffer.from(buffer);

    // Rotate output buffer
    const temp = returnValue[0];
    returnValue[0] = returnValue[1];
    returnValue[1] = returnValue[2];
    returnValue[2] = returnValue[3];
    returnValue[3] = temp;

    // Apply S-Box to all 4 bytes
    for (let i = 0; i < 4; i ++) {
      returnValue[i] = Number(Boxes.sBox[returnValue[i]]);
    }

    // Apply XOR with RCon value with the leftmost bit [0]
    returnValue[0] ^= Number(Boxes.rconBox[rconValue]);

    return returnValue;
  }

  // https://en.wikipedia.org/wiki/Rijndael_key_schedule#The_key_schedule
  public static _keyExpansion(keyBuffer: Buffer, keyLength: number): Buffer {
    // Currently only expands a 126 bit key.
    const returnBuffer = Buffer.alloc(176);
    keyBuffer.copy(returnBuffer, 0, 0, keyBuffer.length);
    let n = 16;
    const b = 176;
    let rconValue = 1;

    while (n !== b) {
      console.log(n);
      let temp = Buffer.from(returnBuffer.slice(n - 4, n));
      temp = this._keyExpansionCore(temp, rconValue);
      rconValue++;
      temp = xor(temp, returnBuffer.slice(n - 16, n - 12));
      temp.copy(returnBuffer, n, 0, temp.length);
      n += temp.length;

      for (let i = 0; i < 3; i++) {
        temp = Buffer.from(returnBuffer.slice(n - 4, n));
        temp = xor(temp, returnBuffer.slice(n - 16, n - 12));
        temp.copy(returnBuffer, n, 0, temp.length);
        n += temp.length;
      }
    }

    return returnBuffer;
  }
}
