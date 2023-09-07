export declare namespace Crypto {
    function generateSalt(length: number): string;
    function generatePadding(length: number, char: number): string;
}
export declare namespace RSA {
    function encrypt(plain: string, publicKey: string): string;
}
export declare namespace SHA {
    function sha512(plain: string, salt: string, paddingLength: number): string;
}
