import { AESCore } from './core';
import { KeyGenerator } from './generators';
import { ModeGenerator } from './generators';

export class AES {

  public static generateKey(keyLength: number): string {
    return KeyGenerator.generateKeySync(keyLength).toString('hex');
  }

  public static encrypt(message: string, key: string, keySize: number): string {
    let cipherText = '';
    const keyBuffer = AESCore.keyExpansion(Buffer.from(key, 'hex'), 126);
    const messageBlocks = ModeGenerator.ecbBlockCreation(message);
    const rounds = this._getRounds(keySize);

    for (let state of messageBlocks) {
      // Initial Round key addition
      AESCore.addRoundKeys(state, Buffer.from(key, 'hex'));

      // Loop rounds
      for (let i = 0; i < rounds - 1; i++) {
        AESCore.subBytes(state);
        AESCore.shiftRows(state);
        AESCore.mixColumns(state);
        AESCore.addRoundKeys(state, keyBuffer.slice(16 * (i + 1), (16 * (i + 1) + 16)));
      }

      // Last round
      AESCore.subBytes(state);
      AESCore.shiftRows(state);
      AESCore.addRoundKeys(state, keyBuffer.slice(keyBuffer.length - 16, keyBuffer.length));

      cipherText += state.toString('hex'); // Return a string representation of the state as cipher text
    }

    return cipherText;
  }

  public static decrypt(cipherText: string, key: string, keySize: number): string {
    let plainText = '';
    const keyBuffer = AESCore.keyExpansion(Buffer.from(key, 'hex'), 126);
    const cipherBlocks = ModeGenerator.ecbBlockCreationHex(cipherText);
    const rounds = this._getRounds(keySize);

    for (let state of cipherBlocks) {
      // Inverse of encrypt function
      AESCore.addRoundKeys(state, keyBuffer.slice(keyBuffer.length - 16, keyBuffer.length)); // Add last *first round keys

      for (let i = rounds - 1; i > 0; i--) {
        AESCore.invShiftRows(state);
        AESCore.invSubBytes(state);
        AESCore.addRoundKeys(state, keyBuffer.slice(16 * i, (16 * i + 16)));
        AESCore.invMixColumns(state);
      }

      AESCore.invShiftRows(state);
      AESCore.invSubBytes(state);
      AESCore.addRoundKeys(state, Buffer.from(key, 'hex'));
      plainText += state.toString();
    }

    return plainText;
  }

  private static _getRounds(keySize: number): number {
    switch (keySize) {
      case 192:
        return 12;
      case 256:
        return 14;
      default:
        return 10;
    }
  }
}
