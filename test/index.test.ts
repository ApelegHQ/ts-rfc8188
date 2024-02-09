/* Copyright © 2024 Exact Realty Limited. All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { encodings, decrypt, encrypt } from '../src/index.js';

const ArrayBufferToUint8ArrayStream = (s: ReadableStream<ArrayBufferLike>) =>
	s.pipeThrough(
		new TransformStream<ArrayBufferLike, Uint8Array>({
			start() {},
			transform(chunk, controller) {
				if (ArrayBuffer.isView(chunk)) {
					controller.enqueue(
						new Uint8Array(
							chunk.buffer,
							chunk.byteOffset,
							chunk.byteLength,
						),
					);
				} else {
					controller.enqueue(new Uint8Array(chunk));
				}
			},
		}),
	);

describe('RFC 8188', () => {
	it('RFC 8188 § 3.1', async function () {
		const data = Buffer.from(
			'I1BsxtFttlv3u_Oo94xnmwAAEAAA-NAVub2qFgBEuQKRapoZu-IxkIva3MEB1PD-' +
				'ly8Thjg',
			'base64url',
		);
		const encryptedStream = new Response(data).body;
		assert.ok(!!encryptedStream);
		const decryptedStream = decrypt(
			encodings.aes128gcm,
			encryptedStream,
			(keyId) => {
				assert.equal(keyId.byteLength, 0);
				return Buffer.from('yqdlZ-tYemfogSmv7Ws5PQ', 'base64url');
			},
		);
		const result = await new Response(
			ArrayBufferToUint8ArrayStream(decryptedStream),
		).arrayBuffer();
		assert.equal(
			Buffer.from(result).toString('base64url'),
			// Note: Example from RFC is wrong, as it includes 'Ag' at the end,
			// which includes the 0x02 delimiter.
			'SSBhbSB0aGUgd2FscnVz',
		);
	});

	it('RFC 8188 § 3.2', async function () {
		const data = Buffer.from(
			'uNCkWiNYzKTnBN9ji3-qWAAAABkCYTHOG8chz_gnvgOqdGYovxyjuqRyJFjEDyoF' +
				'1Fvkj6hQPdPHI51OEUKEpgz3SsLWIqS_uA',
			'base64url',
		);
		const encryptedStream = new Response(data).body;
		assert.ok(!!encryptedStream);
		const decryptedStream = decrypt(
			encodings.aes128gcm,
			encryptedStream,
			(keyId) => {
				assert.equal(keyId.byteLength, 2);
				assert.equal(Buffer.from(keyId).toString(), 'a1');
				return Buffer.from('BO3ZVPxUlnLORbVGMpbT1Q', 'base64url');
			},
		);
		const result = await new Response(
			ArrayBufferToUint8ArrayStream(decryptedStream),
		).arrayBuffer();
		assert.equal(
			Buffer.from(result).toString('base64url'),
			// Note: Example from RFC is wrong, as it includes 'Ag' at the end,
			// which includes the 0x02 delimiter.
			'SSBhbSB0aGUgd2FscnVz',
		);
	});

	it('Decryption max record size', async function () {
		const data = Buffer.from(
			'uNCkWiNYzKTnBN9ji3-qWAAAABkCYTHOG8chz_gnvgOqdGYovxyjuqRyJFjEDyoF' +
				'1Fvkj6hQPdPHI51OEUKEpgz3SsLWIqS_uA',
			'base64url',
		);
		const encryptedStream = new Response(data).body;
		assert.ok(!!encryptedStream);
		const decryptedStream = decrypt(
			encodings.aes128gcm,
			encryptedStream,
			(keyId) => {
				assert.equal(keyId.byteLength, 2);
				assert.equal(Buffer.from(keyId).toString(), 'a1');
				return Buffer.from('BO3ZVPxUlnLORbVGMpbT1Q', 'base64url');
			},
			18,
		);
		await assert.rejects(
			new Response(
				ArrayBufferToUint8ArrayStream(decryptedStream),
			).arrayBuffer(),
			{ name: 'RangeError', message: 'Invalid record size: 25' },
		);
	});

	it('can encrypt and decrypt data', async function () {
		for (let keyId_length = 0; keyId_length < 256; keyId_length += 16) {
			const keyId = new Uint8Array(keyId_length);
			globalThis.crypto.getRandomValues(keyId);

			for (let data_length = 0; data_length < 256; data_length += 16) {
				const data = new Uint8Array(data_length);
				globalThis.crypto.getRandomValues(data);

				for (
					let record_length = 5;
					record_length < 64;
					record_length += 7
				) {
					for (const encoding of Object.values(encodings)) {
						const minRecordLength = encoding.tag_length + 2;
						const key = new Uint8Array(
							((0, Math.random)() * 50) | 0,
						);
						globalThis.crypto.getRandomValues(key);

						const sourceStream = new Response(data).body;
						assert.ok(!!sourceStream);
						const encryptedStream = await encrypt(
							encoding,
							sourceStream,
							record_length,
							keyId,
							key,
						)
							.catch((e) => {
								if (record_length < minRecordLength) {
									return;
								}
								throw e;
							})
							.then((v) => {
								if (v && record_length < minRecordLength) {
									throw new Error('Should have failed');
								}
								return v;
							});
						if (
							record_length < minRecordLength &&
							!encryptedStream
						) {
							continue;
						}
						assert.ok(!!encryptedStream);

						const decryptedStream = decrypt(
							encoding,
							encryptedStream,
							(pKeyId) => {
								assert.equal(pKeyId.byteLength, keyId_length);
								assert.deepEqual(
									Buffer.from(pKeyId),
									Buffer.from(keyId),
								);
								return key;
							},
						);
						const result = await new Response(
							ArrayBufferToUint8ArrayStream(decryptedStream),
						).arrayBuffer();
						assert.deepEqual(
							Buffer.from(result),
							Buffer.from(data),
						);
					}
				}
			}
		}
	});
});
