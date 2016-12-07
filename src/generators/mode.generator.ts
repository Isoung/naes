export class ModeGenerator {
  public static ecbBlockCreation(str: String): Buffer[] {
    const returnValue = Array<Buffer>();

    while (str.length !== 0) {
      if (str.length >= 16) {
        returnValue.push(Buffer.from(str.slice(0, 16)));
      }
      else {
        returnValue.push(this._addPadding(Buffer.from(str.slice(0, 16))));
      }
      str = str.slice(16, str.length);
    }

    return returnValue;
  }

  public static ecbBlockCreationHex(str: String): Buffer[] {
    const returnValue = Array<Buffer>();

    while (str.length !== 0) {
      returnValue.push(Buffer.from(str.slice(0, 32), 'hex'));
      str = str.slice(32, str.length);
    }

    return returnValue;
  }

  private static _addPadding(buffer: Buffer): Buffer {
    const diff = 16 - buffer.length;
    let tBuffer = Buffer.alloc(diff, diff);
    tBuffer = Buffer.concat([buffer, tBuffer]);

    return tBuffer;
  }
}
