import test from 'ava';
import encryption, { generateSalt } from '../index.js';

test('Encrypting a message makes it unlegible', async t => {
    const message = 'foobar';
    const { cypher, iv } = await encryption().encrypt(message);
    t.not(message, cypher);
});

test('decrypting a cypher makes it legible again', async t => {
    const { encrypt, decrypt } = encryption();
    const original = 'foobar';
    const { cypher, iv } = await encrypt(original);
    const decrypted = await decrypt(cypher, iv);
    t.is(original, decrypted);
});