export declare namespace Crypto {
    function generateSalt(length: number): string;
    function generatePadding(length: number, char: number): string;
}
export declare namespace RSA {
    function encrypt(plain: string, publicKey: string): string;
}
export declare namespace SHA {
    type HashConfig = {
        salt: string;
        paddingLength: number;
        padChar: number;
    };
    function sha512(plain: string, config?: Partial<HashConfig>): string;
}
