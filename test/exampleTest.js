/*
 * ISC License (ISC)
 * Copyright (c) 2018 aeternity developers
 *
 *  Permission to use, copy, modify, and/or distribute this software for any
 *  purpose with or without fee is hereby granted, provided that the above
 *  copyright notice and this permission notice appear in all copies.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
 *  REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 *  AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
 *  INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 *  LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 *  OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 *  PERFORMANCE OF THIS SOFTWARE.
 */
import {hash, personalMessageToBinary, sign} from "@aeternity/aepp-sdk/es/utils/crypto";

const {Universal, Crypto, MemoryAccount, Node} = require('@aeternity/aepp-sdk');

const EXAMPLE_CONTRACT_PATH = utils.readFileRelative('./contracts/ExampleContract.aes', 'utf-8');

const config = {
    url: 'http://localhost:3001/',
    internalUrl: 'http://localhost:3001/internal/',
    compilerUrl: 'http://localhost:3080'
};

describe('Example Contract', () => {

    let client, contract;

    before(async () => {
        client = await Universal({
            nodes: [{
                name: 'devnetNode',
                instance: await Node(config)
            }],
            accounts: [MemoryAccount({
                keypair: wallets[0]
            })],
            networkId: 'ae_devnet',
            compilerUrl: config.compilerUrl
        });
    });

    it('Deploying Example Contract', async () => {
        contract = await client.getContractInstance(EXAMPLE_CONTRACT_PATH);

        const init = await contract.methods.init();
        assert.equal(init.result.returnType, 'ok');
    });

    it('Signature verification', async () => {
        let url = "https://github.com/aeternity/protocol/blob/master/contracts/sophia.md";
        let hash = Crypto.hash(url);
        assert.equal(hash.toString('hex'), (await contract.methods.hash(url)).decodedResult);

        // signPersonalMessage takes a string, but our hash is already Buffer, so we use plain sign
        let sig = Crypto.sign(hash, Buffer.from(wallets[0].secretKey, 'hex'));

        const res = await contract.methods.test_verify(url, wallets[0].publicKey, sig);
        assert.equal(res.decodedResult, true);
    });


    it('Signature verification: with prefix', async () => {
        let url = "https://github.com/aeternity/protocol/blob/master/contracts/sophia.md";

        let hash = Crypto.hash(Crypto.personalMessageToBinary(url));

        // signPersonalMessage takes a string, but our hash is already Buffer, so we use plain sign
        let sig = Crypto.signPersonalMessage(url, Buffer.from(wallets[0].secretKey, 'hex'));

        const res = await contract.methods.test_verify_personal_message(hash.toString('hex'), wallets[0].publicKey, sig);
        assert.equal(res.decodedResult, true);
    });

    it('Signature verification: with prefix', async () => {
        let url = "https://github.com/aeternity/protocol/blob/master/contracts/sophia.md";

        let personalMessage = Crypto.personalMessageToBinary(url);
        assert.equal(personalMessage.toString(), (await contract.methods.prefix_message(url)).decodedResult);

        // signPersonalMessage takes a string, but our hash is already Buffer, so we use plain sign
        let sig = Crypto.signPersonalMessage(url, Buffer.from(wallets[0].secretKey, 'hex'));

        const res = await contract.methods.test_verify_prefix(url, wallets[0].publicKey, sig);
        assert.equal(res.decodedResult, true);
    });

    it('Signature verification: with custom prefix', async () => {
        let url = "https://github.com/aeternity/protocol/blob/master/contracts/sophia.md";

        function personalMessageToBinary (message) {
            const p = Buffer.from('aeternity Signed Message:\n', 'utf8')
            const msg = Buffer.from(message, 'utf8')
            if (msg.length >= 0xFD) throw new Error('message too long')
            return Buffer.concat([Buffer.from(p.length.toString(), 'utf8'), p, Buffer.from(msg.length.toString(), 'utf8'), msg])
        }

        let personalMessage = personalMessageToBinary(url);
        assert.equal(personalMessage.toString(), (await contract.methods.prefix_message(url)).decodedResult);

        function signPersonalMessage (message, privateKey) {
            return Crypto.sign(Crypto.hash(personalMessageToBinary(message)), privateKey)
        }

        // signPersonalMessage takes a string, but our hash is already Buffer, so we use plain sign
        let sig = signPersonalMessage(url, Buffer.from(wallets[0].secretKey, 'hex'));

        const res = await contract.methods.test_verify_prefix(url, wallets[0].publicKey, sig);
        assert.equal(res.decodedResult, true);
    });
});
