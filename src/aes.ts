import { AESCore } from './core';
import { KeyGenerator } from './generators';
import { ModeGenerator } from './generators';

export class AES {

  public static generateKey(keyLength: number): string {
    return KeyGenerator.generateKeySync(keyLength).toString('hex');
  }

  public static encrypt(message: string, key: string, keySize: number) {
    const keyBuffer = Buffer.from(key, 'hex');
    const messageBlocks = ModeGenerator.ecbBlockCreation(message);
    const rounds = this._getRounds(keySize);

    // Initial Round key addition
    AESCore.addRoundKeys();

    // Loop rounds
    for (let i = 0; i < rounds - 1; i++) {
      AESCore.subBytes();
      AESCore.shiftRows();
      AESCore.mixColumns();
      AESCore.addRoundKeys();
    }

    // Last round
    AESCore.subBytes();
    AESCore.shiftRows();
    AESCore.addRoundKeys();
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
