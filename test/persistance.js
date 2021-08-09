import test from 'ava';
import encryption, { generateSalt } from '../index.js';

const salt = generateSalt();
const password = '2@4ZNyxSijhUXYrQ';
const original = 'foobar';

test('the key can be reused', async t => {
    // first use
    const { encrypt } = encryption(password, salt);
    const { cypher, iv } = await encrypt(original);

    // second use
    const { decrypt } = encryption(password, salt);
    const decrypted = await decrypt(cypher, iv);

    t.is(original, decrypted);
});

test(`using the wrong password won't decrypt a cypher`, async t => {
    // first use
    const { encrypt } = encryption(password, salt);
    const { cypher, iv } = await encrypt(original);

    // second use
    const { decrypt } = encryption(password + '1', salt);
    const decrypted = await decrypt(cypher, iv);

    t.throws(
        () => decrypt(cypher, iv),
        { message: 'decryption failed' }
    );
});


test(`using the wrong salt won't decrypt a cypher`, async t => {
    // first use
    const { encrypt } = encryption(password, salt);
    const { cypher, iv } = await encrypt(original);

    // second use
    const { decrypt } = encryption(password, generateSalt());
    const decrypted = await decrypt(cypher, iv);

    t.throws(
        () => decrypt(cypher, iv),
        { message: 'decryption failed' }
    );
});
