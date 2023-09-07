import {sha512 as js_sha512} from "js-sha512";
import {JSEncrypt} from "jsencrypt";

export namespace Crypto {
    function getRandomInt(minInclusive: number, maxExclusive: number): number {
        minInclusive = Math.ceil(minInclusive);
        maxExclusive = Math.floor(maxExclusive);
        return Math.floor(Math.random() * (maxExclusive - minInclusive)) + minInclusive; //최댓값은 제외, 최솟값은 포함
    }

    export function generateSalt(length: number): string {
        let salt = '';
        while (salt.length < length) {
            const type = getRandomInt(0, 3);
            switch (type) {
                case 0:
                    salt += String.fromCharCode(getRandomInt(48, 58));
                    break;
                case 1:
                    salt += String.fromCharCode(getRandomInt(65, 91));
                    break;
                case 2:
                    salt += String.fromCharCode(getRandomInt(97, 122));
                    break;
            }
        }

        return salt;
    }

    export function generatePadding(length: number, char: number): string {
        return String.fromCharCode(char).repeat(length)
    }
}

export namespace RSA {
    export function encrypt(plain: string, publicKey: string): string {
        const encrypt = new JSEncrypt()
        encrypt.setPublicKey(publicKey)

        const encrypted = encrypt.encrypt(plain)
        if (encrypted === false) {
            throw new Error(`Cannot encrypt: plain=${plain}, publicKey=${publicKey}`)
        } else {
            return encrypted
        }
    }
}

export namespace SHA {
    export function sha512(plain: string, salt: string, paddingLength: number): string {
        let m = plain + salt
        m += Crypto.generatePadding(paddingLength - m.length, 65)

        return js_sha512(m)
    }
}