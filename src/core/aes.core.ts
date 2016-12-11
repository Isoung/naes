import { Boxes } from '.';
import xor = require('bitwise-xor');

export class AESCore {
  // States passed in refer to buffers in memory. Any changes to the state will be reflected to the
  // same buffer outside of the function.
  // https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#The_SubBytes_step
  public static subBytes(state: Buffer): void {
    for (let i = 0; i < state.length; i++) {
      state[i] = Number(Boxes.sBox[state[i]]);
    }
  }

  // https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#The_ShiftRows_step
  public static shiftRows(state: Buffer): void {
    const tempBuffer = Buffer.from(state);

    // [00][04][08][12] Elements 0, 4, 8 , 12 do not change as they are considered the 1st row
    // [01][05][09][13] >> [05][09][13][01]
    // [02][06][10][14] >> [10][14][02][06]
    // [03][07][11][15] >> [15][03][07][11]
    state[1] = tempBuffer[5];
    state[2] = tempBuffer[10];
    state[3] = tempBuffer[15];

    state[5] = tempBuffer[9];
    state[6] = tempBuffer[14];
    state[7] = tempBuffer[3];

    state[9] = tempBuffer[13];
    state[10] = tempBuffer[2];
    state[11] = tempBuffer[7];

    state[13] = tempBuffer[1];
    state[14] = tempBuffer[6];
    state[15] = tempBuffer[11];
  }

  // https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#The_MixColumns_step
  public static mixColumns(state: Buffer): void {
    const tempBuffer = Buffer.from(state);

    state[0] = Number(Boxes.mx2Box[tempBuffer[0]]) ^ Number(Boxes.mx3Box[tempBuffer[1]]) ^ tempBuffer[2] ^ tempBuffer[3];
    state[1] = tempBuffer[0] ^ Number(Boxes.mx2Box[tempBuffer[1]]) ^ Number(Boxes.mx3Box[tempBuffer[2]]) ^ tempBuffer[3];
    state[2] = tempBuffer[0] ^ tempBuffer[1] ^ Number(Boxes.mx2Box[tempBuffer[2]]) ^ Number(Boxes.mx3Box[tempBuffer[3]]);
    state[3] = Number(Boxes.mx3Box[tempBuffer[0]]) ^ tempBuffer[1] ^ tempBuffer[2] ^ Number(Boxes.mx2Box[tempBuffer[3]]);

    state[4] = Number(Boxes.mx2Box[tempBuffer[4]]) ^ Number(Boxes.mx3Box[tempBuffer[5]]) ^ tempBuffer[6] ^ tempBuffer[7];
    state[5] = tempBuffer[4] ^ Number(Boxes.mx2Box[tempBuffer[5]]) ^ Number(Boxes.mx3Box[tempBuffer[6]]) ^ tempBuffer[7];
    state[6] = tempBuffer[4] ^ tempBuffer[5] ^ Number(Boxes.mx2Box[tempBuffer[6]]) ^ Number(Boxes.mx3Box[tempBuffer[7]]);
    state[7] = Number(Boxes.mx3Box[tempBuffer[4]]) ^ tempBuffer[5] ^ tempBuffer[6] ^ Number(Boxes.mx2Box[tempBuffer[7]]);

    state[8] = Number(Boxes.mx2Box[tempBuffer[8]]) ^ Number(Boxes.mx3Box[tempBuffer[9]]) ^ tempBuffer[10] ^ tempBuffer[11];
    state[9] = tempBuffer[8] ^ Number(Boxes.mx2Box[tempBuffer[9]]) ^ Number(Boxes.mx3Box[tempBuffer[10]]) ^ tempBuffer[11];
    state[10] = tempBuffer[8] ^ tempBuffer[9] ^ Number(Boxes.mx2Box[tempBuffer[10]]) ^ Number(Boxes.mx3Box[tempBuffer[11]]);
    state[11] = Number(Boxes.mx3Box[tempBuffer[8]]) ^ tempBuffer[9] ^ tempBuffer[10] ^ Number(Boxes.mx2Box[tempBuffer[11]]);

    state[12] = Number(Boxes.mx2Box[tempBuffer[12]]) ^ Number(Boxes.mx3Box[tempBuffer[13]]) ^ tempBuffer[14] ^ tempBuffer[15];
    state[13] = tempBuffer[12] ^ Number(Boxes.mx2Box[tempBuffer[13]]) ^ Number(Boxes.mx3Box[tempBuffer[14]]) ^ tempBuffer[15];
    state[14] = tempBuffer[12] ^ tempBuffer[13] ^ Number(Boxes.mx2Box[tempBuffer[14]]) ^ Number(Boxes.mx3Box[tempBuffer[15]]);
    state[15] = Number(Boxes.mx3Box[tempBuffer[12]]) ^ tempBuffer[13] ^ tempBuffer[14] ^ Number(Boxes.mx2Box[tempBuffer[15]]);
  }

  // https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#The_AddRoundKey_step
  public static addRoundKeys(state: Buffer, roundKey: Buffer): void {
    for (let i = 0; i < state.length; i++) {
      state[i] ^= roundKey[i];
    }
  }

  // http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf 5.3.1
  public static invShiftRows(state: Buffer) {
    const tempBuffer = Buffer.from(state);

    // [00][04][08][12] Elements 0, 4, 8 , 12 do not change as they are considered the 1st row
    // [01][05][09][13] >> [13][01][05][09]
    // [02][06][10][14] >> [10][14][02][06]
    // [03][07][11][15] >> [07][11][15][03]
    state[1] = tempBuffer[13];
    state[2] = tempBuffer[10];
    state[3] = tempBuffer[7];

    state[5] = tempBuffer[1];
    state[6] = tempBuffer[14];
    state[7] = tempBuffer[11];

    state[9] = tempBuffer[5];
    state[10] = tempBuffer[2];
    state[11] = tempBuffer[15];

    state[13] = tempBuffer[9];
    state[14] = tempBuffer[6];
    state[15] = tempBuffer[3];
  }

  // http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf 5.3.2
  public static invSubBytes(state: Buffer) {
    for (let i = 0; i < state.length; i++) {
      state[i] = Number(Boxes.inverseSBox[state[i]]);
    }
  }

  // http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf 5.3.3
  public static invMixColumns(state: Buffer) {
    // 09 11 13 14
    // 09 0b 0d 0e

    // 14 11 13 09
    // 09 14 11 13
    // 13 09 14 11
    // 11 13 09 14
    const tempBuffer = Buffer.from(state);

    state[0] = Number(Boxes.mx14Box[tempBuffer[0]]) ^ Number(Boxes.mx11Box[tempBuffer[1]]) ^ Number(Boxes.mx13Box[tempBuffer[2]]) ^ Number(Boxes.mx9Box[tempBuffer[3]]);
    state[1] = Number(Boxes.mx9Box[tempBuffer[0]]) ^ Number(Boxes.mx14Box[tempBuffer[1]]) ^ Number(Boxes.mx11Box[tempBuffer[2]]) ^ Number(Boxes.mx13Box[tempBuffer[3]]);
    state[2] = Number(Boxes.mx13Box[tempBuffer[0]]) ^ Number(Boxes.mx9Box[tempBuffer[1]]) ^ Number(Boxes.mx14Box[tempBuffer[2]]) ^ Number(Boxes.mx11Box[tempBuffer[3]]);
    state[3] = Number(Boxes.mx11Box[tempBuffer[0]]) ^ Number(Boxes.mx13Box[tempBuffer[1]]) ^ Number(Boxes.mx9Box[tempBuffer[2]]) ^ Number(Boxes.mx14Box[tempBuffer[3]]);

    state[4] = Number(Boxes.mx14Box[tempBuffer[4]]) ^ Number(Boxes.mx11Box[tempBuffer[5]]) ^ Number(Boxes.mx13Box[tempBuffer[6]]) ^ Number(Boxes.mx9Box[tempBuffer[7]]);
    state[5] = Number(Boxes.mx9Box[tempBuffer[4]]) ^ Number(Boxes.mx14Box[tempBuffer[5]]) ^ Number(Boxes.mx11Box[tempBuffer[6]]) ^ Number(Boxes.mx13Box[tempBuffer[7]]);
    state[6] = Number(Boxes.mx13Box[tempBuffer[4]]) ^ Number(Boxes.mx9Box[tempBuffer[5]]) ^ Number(Boxes.mx14Box[tempBuffer[6]]) ^ Number(Boxes.mx11Box[tempBuffer[7]]);
    state[7] = Number(Boxes.mx11Box[tempBuffer[4]]) ^ Number(Boxes.mx13Box[tempBuffer[5]]) ^ Number(Boxes.mx9Box[tempBuffer[6]]) ^ Number(Boxes.mx14Box[tempBuffer[7]]);

    state[8] = Number(Boxes.mx14Box[tempBuffer[8]]) ^ Number(Boxes.mx11Box[tempBuffer[9]]) ^ Number(Boxes.mx13Box[tempBuffer[10]]) ^ Number(Boxes.mx9Box[tempBuffer[11]]);
    state[9] = Number(Boxes.mx9Box[tempBuffer[8]]) ^ Number(Boxes.mx14Box[tempBuffer[9]]) ^ Number(Boxes.mx11Box[tempBuffer[10]]) ^ Number(Boxes.mx13Box[tempBuffer[11]]);
    state[10] = Number(Boxes.mx13Box[tempBuffer[8]]) ^ Number(Boxes.mx9Box[tempBuffer[9]]) ^ Number(Boxes.mx14Box[tempBuffer[10]]) ^ Number(Boxes.mx11Box[tempBuffer[11]]);
    state[11] = Number(Boxes.mx11Box[tempBuffer[8]]) ^ Number(Boxes.mx13Box[tempBuffer[9]]) ^ Number(Boxes.mx9Box[tempBuffer[10]]) ^ Number(Boxes.mx14Box[tempBuffer[11]]);

    state[12] = Number(Boxes.mx14Box[tempBuffer[12]]) ^ Number(Boxes.mx11Box[tempBuffer[13]]) ^ Number(Boxes.mx13Box[tempBuffer[14]]) ^ Number(Boxes.mx9Box[tempBuffer[15]]);
    state[13] = Number(Boxes.mx9Box[tempBuffer[12]]) ^ Number(Boxes.mx14Box[tempBuffer[13]]) ^ Number(Boxes.mx11Box[tempBuffer[14]]) ^ Number(Boxes.mx13Box[tempBuffer[15]]);
    state[14] = Number(Boxes.mx13Box[tempBuffer[12]]) ^ Number(Boxes.mx9Box[tempBuffer[13]]) ^ Number(Boxes.mx14Box[tempBuffer[14]]) ^ Number(Boxes.mx11Box[tempBuffer[15]]);
    state[15] = Number(Boxes.mx11Box[tempBuffer[12]]) ^ Number(Boxes.mx13Box[tempBuffer[13]]) ^ Number(Boxes.mx9Box[tempBuffer[14]]) ^ Number(Boxes.mx14Box[tempBuffer[15]]);
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
  public static keyExpansion(keyBuffer: Buffer, keyLength: number): Buffer {
    const returnBuffer = Buffer.alloc(this._getKeySizes(keyLength));
    keyBuffer.copy(returnBuffer, 0, 0, keyBuffer.length);
    let n = this._getRoundKeySizes(keyLength);
    const b = this._getKeySizes(keyLength);
    let rconValue = 1;

    while (n !== b) {
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

  private static _getKeySizes(keyLength: number): number {
    switch (keyLength) {
      case 192:
        return 208;
      case 256:
        return 240;
      default:
        return 176;
    }
  }

  private static _getRoundKeySizes(keyLength: number): number {
    switch (keyLength) {
      case 192:
        return 24;
      case 256:
        return 32;
      default:
        return 16;
    }
  }
}
