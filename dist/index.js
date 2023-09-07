import { sha512 as js_sha512 } from "js-sha512";
import { JSEncrypt } from "jsencrypt";
export var Crypto;
(function (Crypto) {
    function getRandomInt(minInclusive, maxExclusive) {
        minInclusive = Math.ceil(minInclusive);
        maxExclusive = Math.floor(maxExclusive);
        return Math.floor(Math.random() * (maxExclusive - minInclusive)) + minInclusive; //최댓값은 제외, 최솟값은 포함
    }
    function generateSalt(length) {
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
    Crypto.generateSalt = generateSalt;
    function generatePadding(length, char) {
        return String.fromCharCode(char).repeat(length);
    }
    Crypto.generatePadding = generatePadding;
})(Crypto || (Crypto = {}));
export var RSA;
(function (RSA) {
    function encrypt(plain, publicKey) {
        const encrypt = new JSEncrypt();
        encrypt.setPublicKey(publicKey);
        const encrypted = encrypt.encrypt(plain);
        if (encrypted === false) {
            throw new Error(`Cannot encrypt: plain=${plain}, publicKey=${publicKey}`);
        }
        else {
            return encrypted;
        }
    }
    RSA.encrypt = encrypt;
})(RSA || (RSA = {}));
export var SHA;
(function (SHA) {
    function sha512(plain, config) {
        const salt = config?.salt ?? '';
        const paddingLength = config?.paddingLength ?? 0;
        const padChar = config?.padChar ?? 80;
        let m = plain + salt;
        m += Crypto.generatePadding(Math.max(paddingLength - m.length, 0), padChar);
        return js_sha512(m);
    }
    SHA.sha512 = sha512;
})(SHA || (SHA = {}));
