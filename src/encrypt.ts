/* Copyright © 2024 Apeleg Limited. All rights reserved.
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

import {
	MAX_KEY_ID_LENGTH,
	MAX_RECORD_SIZE,
	PADDING_DELIMITER_NONTERMINAL,
	PADDING_DELIMITER_TERMINAL,
	SALT_LENGTH,
} from './constants.js';
import type { TEncoding } from './encodings.js';
import init from './init.js';
import sharedBufferToUint8Array from './lib/sharedBufferToUint8Array.js';

/**
 * Generates a random salt for cryptographic purposes.
 *
 * @returns A randomly generated salt as a Uint8Array.
 */
const generateRandomSalt = () => {
	const salt = new Uint8Array(SALT_LENGTH);
	globalThis.crypto.getRandomValues(salt);

	return salt;
};

/**
 * Encrypts data using the aes128gcm content encoding.
 *
 * @param encoding - The encoding configuration.
 * @param data - The data to be encrypted (plaintext).
 * @param recordSize - The size of each record.
 * @param keyId - The key ID used for encryption.
 * @param IKM - The Initial Keying Material.
 * @param salt - Optional salt for key derivation. If none is provided, a random
 *   salt will be generated.
 * @returns A readable stream
 *   containing the encrypted data (ciphertext).
 * @throws {RangeError} - Throws if the record size is invalid, the key ID is
 *   too long or the salt has an incorrect length.
 */
const encrypt = async (
	encoding: Readonly<TEncoding>,
	data: Readonly<ReadableStream<Readonly<BufferSource>>>,
	recordSize: number,
	keyId: Readonly<ArrayBufferLike>,
	IKM: Readonly<ArrayBufferLike>,
	salt?: Readonly<ArrayBufferLike> | null | undefined,
): Promise<ReadableStream<ArrayBufferLike>> => {
	if (recordSize <= encoding.tag_length + 1 || recordSize > MAX_RECORD_SIZE) {
		throw new RangeError('Invalid record size: ' + recordSize);
	}

	if (keyId.byteLength > MAX_KEY_ID_LENGTH) {
		throw new RangeError('Key ID too long');
	}

	if (salt && salt.byteLength !== SALT_LENGTH) {
		throw new RangeError('Invald salt length: ' + salt.byteLength);
	}

	const segmentSize = recordSize - encoding.tag_length - 1;
	const saltBuf = salt
		? sharedBufferToUint8Array(salt)
		: generateRandomSalt();

	const [CEK, deriveNonce] = await init(encoding, IKM, saltBuf, ['encrypt']);
	IKM = void 0 as unknown as typeof IKM;

	const buffer = new Uint8Array(segmentSize);
	// Position within `buffer`
	let pos = 0;

	const result = new TransformStream<BufferSource, ArrayBufferLike>({
		['start']: (controller) => {
			// As the stream gets started, the header can be pushed immediately
			// The header contains:
			//   (1) The salt (fixed 16 bytes length)
			//   (2) The record length (fixed 4 bytes length)
			//   (3) The key ID length (fixed 1 byte length)
			//   (4) The key ID (variable length, as per (3))
			const headerLength = saltBuf.byteLength + 4 + 1 + keyId.byteLength;
			const header = new ArrayBuffer(headerLength);
			const saltPart = new Uint8Array(header, 0, saltBuf.byteLength);
			saltPart.set(saltBuf);

			const dataView = new DataView(header, saltBuf.byteLength, 4 + 1);
			dataView.setUint32(0, recordSize, false);
			dataView.setUint8(4, keyId.byteLength);

			const keyIdPart = new Uint8Array(
				header,
				saltBuf.byteLength + 4 + 1,
				keyId.byteLength,
			);
			const keyIdBuf = sharedBufferToUint8Array(keyId);
			keyIdPart.set(keyIdBuf);

			controller.enqueue(header);
		},
		['transform']: async (chunk, controller) => {
			// As data become available, it can be encrypted
			const octets = sharedBufferToUint8Array(chunk);
			// Position within `chunk`
			let ipos = 0;

			// The following loop ensures that records are filled as much
			// as possible
			while (ipos < chunk.byteLength) {
				const subArray = octets.subarray(
					ipos,
					ipos + segmentSize - pos,
				);
				buffer.set(subArray, pos);
				pos += subArray.byteLength;
				ipos += subArray.byteLength;
				if (pos === segmentSize) {
					const nonce = deriveNonce.next();
					const iv = nonce.value;
					const record = new Uint8Array(segmentSize + 1);
					record.set(buffer.subarray(0, pos));
					record[pos] = PADDING_DELIMITER_NONTERMINAL;
					const result = await globalThis.crypto.subtle.encrypt(
						{
							['name']: encoding.params['name'],
							['iv']: iv,
							['tagLength']: encoding.tag_length << 3,
						},
						CEK,
						record,
					);
					controller.enqueue(result);
					pos = 0;
				}
			}
		},
		['flush']: async (controller) => {
			// When no more data are available, send any buffered data
			// If there are no buffered data, send an end-of-record (a record
			// with just the terminal delimiter)
			const nonce = deriveNonce.next();
			const iv = nonce.value;
			const record = new Uint8Array(pos + 1);
			record.set(buffer.subarray(0, pos));
			record[pos] = PADDING_DELIMITER_TERMINAL;
			const result = await globalThis.crypto.subtle.encrypt(
				{
					['name']: encoding.params['name'],
					['iv']: iv,
					['tagLength']: encoding.tag_length << 3,
				},
				CEK,
				record,
			);
			controller.enqueue(result);
			buffer.fill(0);
			record.fill(0);
		},
	});

	data.pipeThrough(result);

	return result.readable;
};

export default encrypt;
