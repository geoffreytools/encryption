# encryption

A wrapper around `crypto.subtle` with a simple API and the following features:
- derive a key from a password with PBKDF2
- or generate a single use random key
- encrypt text with AES in Galois/Counter Mode.

Deriving a key requires a salt, which must be saved in order to be able to regenerate the same key from the same password.

AES-GCM uses an initialization vector (iv) to randomise the encryption. Each encrypted message can and must be stored along with its associated iv.

## How to install

```
npm install https://github.com/geoffreyTools/encryption.git
```

## How to use

```javascript
import encryption, { generateSalt } from 'encryption';

const password = '2@4ZNyxSijhUXYrQ';
const salt = generateSalt();

const { encrypt, decrypt } = encryption(password, salt);

const log = x => (console.log(x), x);

encrypt('message')
    .then(log) // { cipher: 'Nu/mxRj0GArC7NVCNHqcR7CnBS6iDBc=', iv: 'Nw/4KTuLGCiCHbnU' }
    .then(decrypt);
    .then(log) // 'message'
```

## `generateSalt`
### Syntax
```
const salt = generateSalt();
```
### Return value

- `salt`: a bas64 String.

## `encryption`
### Syntax
```
const { encrypt, decrypt } = encryption();
const { encrypt, decrypt } = encryption(password, salt [, iterations]);
```
### Parameters
- `password` (optional): a plain text password
- `salt` (optional): a base64 String as generated by `generateSalt`.
- `iterations` (optional): the number of times the hash function will be executed.\
The default is 1000000. The higher the better.

The salt is required for persistance if you supply a password.
### Return value
a plain `{ encrypt, decrypt }` object.

- `encrypt`: a function seeded with the encryption key which accepts a String to encrypt and returns a `Promise` of a `{ cipher, iv }` pair (which are base64 encoded Strings).
    ```
    const { cipher, iv } = encrypt(message);
    ```

- `decrypt`: a function seeded with the encryption key which returns a `Promise` of a String.
    ```
    const decrypted = decrypt({ cipher, iv });
    ```

## `pbkdf2Hash`
The function responsible for deriving a key.

### Syntax

```
const derived_key = await pbkdf2Hash(password, salt, iterations);
```

### Parameters
They are the same as `encryption`:
- `password`: a plain text password
- `salt`: a base64 String as generated by `generateSalt`.
- `iterations`: the number of times the hash function will be executed.


### Return value
A promise of a base64 encoded string.

### Example

Can be used alone to save passwords:
```javascript
const savePassword = (db, password) => {
    const salt = generateSalt();
    const iterations = 10**5;
    const derived_key = await pbkdf2Hash(password, salt, iterations);
    return db.put({ id: 'password', iterations, derived_key, salt });
}
```
And authenticate users:
```javascript
const authenticate = (db, password) => 
    db.get('password').then(({ derived_key, salt, iterations }) =>
        pbkdf2Hash(password, salt, iterations).then(hash =>
            hash === derived_key
            ? Promise.resolve()
            : Promise.reject('Authentication failed')
        )
    )
```
The examples above are just that: examples. Do not take security advice from me.
