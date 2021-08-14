export const generateSalt = () =>
    pack(crypto.getRandomValues(new Uint8Array(16)));

const pack = buffer => btoa(
    String.fromCharCode.apply(null, new Uint8Array(buffer))
);

const unpack = packed => {
    const string = window.atob(packed)
    const buffer = new ArrayBuffer(string.length)
    const view = new Uint8Array(buffer)
    return view.map((_, i) => string.charCodeAt(i));
};

const keyDerivationAlgorithm = (salt, iterations = 1000000) => ({
    name: "PBKDF2",
    salt,
    iterations,
    hash: "SHA-256"
});

const encryptionAlgorithm = {
    name: 'AES-GCM',
    length: 256
};

const extractable = false;
const keyUsages = ['encrypt', 'decrypt'];

const key = {
    generate: () =>
        crypto.subtle.generateKey(
            encryptionAlgorithm,
            extractable,
            keyUsages
        ),

    import: password =>
        crypto.subtle.importKey(
            "raw",
            new TextEncoder().encode(password),
            "PBKDF2",
            false,
            ["deriveBits", "deriveKey"]
        ),

    export: key => 
        crypto.subtle.exportKey("raw", key).then(pack),

    deriveFrom: (password, salt = generateSalt(), iterations) => 
        key.import(password)
            .then(imported =>
                crypto.subtle.deriveKey(
                    keyDerivationAlgorithm(unpack(salt), iterations),
                    imported,
                    encryptionAlgorithm,
                    extractable,
                    keyUsages
                )
            )
};

const decryption = {
    decode: bytes => new TextDecoder().decode(bytes),

    decrypt: (cipher, key, iv) =>
        crypto.subtle.decrypt({name: 'AES-GCM', iv}, key, cipher),


    read: futureKey => ({cipher, iv}) => 
        futureKey
            .then(key => decryption.decrypt(
                unpack(cipher), key, unpack(iv)))
            .then(decryption.decode, () => Error('decryption failed'))
};


const encryption = {
    encode: data => new TextEncoder().encode(data),

    generateIv: () => crypto.getRandomValues(new Uint8Array(12)),

    encrypt: (encoded, key, iv) => 
        crypto.subtle.encrypt({
            name: 'AES-GCM',
            iv: iv,
        }, key, encoded),

    write: futureKey => message => {
        const iv = encryption.generateIv();
        const encoded = encryption.encode(message)
        return futureKey
            .then(key => encryption.encrypt(encoded, key, iv))
            .then(cipher => ({
                cipher: pack(cipher),
                iv: pack(iv)
            }));
    }
};

export const pbkdf2Hash = (password, salt, iterations) =>
    key.import(password)
        .then(imported => {
            const extractable = true;
            const keyUsages = [];
            return crypto.subtle.deriveKey(
                keyDerivationAlgorithm(unpack(salt), iterations),
                imported,
                encryptionAlgorithm,
                extractable,
                keyUsages
            )
        })
        .then(key.export)


      

export default (password, salt, iterations) => {
    const futureKey = password !== undefined
        ? key.deriveFrom(password, salt, iterations)
        : key.generate();
    
    return {
        decrypt: decryption.read(futureKey),
        encrypt: encryption.write(futureKey),
    };
};