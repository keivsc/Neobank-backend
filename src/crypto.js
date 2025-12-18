import { publicEncrypt, constants, pbkdf2 } from 'crypto';
import { toPEM } from './utils.js';

export function encryptKey(publicKey, wrapKey) {
  return publicEncrypt(
    {
      key: toPEM(Buffer.from(publicKey, "base64")),
      padding: constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    },
    Buffer.from(wrapKey)
  ).toString('base64');
}

export function hashPassword(password, salt) {
    return new Promise((resolve, reject) => {
        pbkdf2(
            password,
            salt,
            200000,
            32,
            "sha256",
            (err, derivedKey) => {
                if (err) return reject(err);

                resolve({
                    hash: derivedKey.toString("base64"),
                    salt: Buffer.from(salt).toString("base64")
                });
            }
        );
    });
}
