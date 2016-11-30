import * as crypto from 'crypto';
import * as randomstring from 'randomstring';
import { Boxes } from './../core';

export class KeyGenerator{
  // Returns a Promise that generates a secret key
  public static generateKey(keyLength: number): Promise<any> {
    return new Promise((resolve, reject) => {
      const salt = randomstring.generate(keyLength);
      crypto.pbkdf2(new Date().toISOString(), salt, keyLength, 126, 'SHA256', (err, key) => {
        if (err) { reject(err); }
        resolve(key);
      });
    });
  }

  public static generateKeySync(keyLength: number): Buffer {
    const salt = randomstring.generate(keyLength);
    const test = crypto.pbkdf2Sync(new Date().toISOString(), salt, keyLength, 126, 'SHA256');
    return test;
  }
}
