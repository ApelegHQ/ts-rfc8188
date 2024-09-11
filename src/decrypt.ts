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
	MAX_RECORD_SIZE,
	PADDING_DELIMITER_NONTERMINAL,
	PADDING_DELIMITER_TERMINAL,
	SALT_LENGTH,
} from './constants.js';
import type { TEncoding } from './encodings.js';
import init from './init.js';
import sharedBufferToUint8Array from './lib/sharedBufferToUint8Array.js';

const DECRYPT_STATE = {
	salt: {},
	recordSize: {},
	keyIdLen: {},
	keyId: {},
	payload: {},
	done: {},
};

/**
 * Decrypts data using the aes128gcm content encoding.
 *
 * @param encoding - The encoding configuration.
 * @param data - The data to
 *   be decrypted (ciphertext).
 * @param lookupIKM - A function that looks up the Initial Keying Material (IKM)
 *   based on the provided key ID.
 * @param maxRecordSize - The maximum record size allowed.
 * @returns A readable stream containing the decrypted data (plaintext).
 * @throws Throws if the record size is invalid or the decrypted data are
 *   otherwise malformed.
 */
const decrypt = (
	encoding: Readonly<TEncoding>,
	data: Readonly<ReadableStream<Readonly<BufferSource>>>,
	lookupIKM: (
		keyId: ArrayBufferLike,
	) => ArrayBufferLike | Promise<ArrayBufferLike>,
	maxRecordSize?: number | null | undefined,
): ReadableStream<ArrayBufferLike> => {
	const salt = new Uint8Array(SALT_LENGTH);

	let buffer: Uint8Array;
	let CEK: CryptoKey;
	let deriveNonce: Generator<ArrayBuffer, never, unknown>;
	let recordSize: number = 0;
	// Position within `buffer`
	let pos = 0;
	// keyId stores its length (one octet long) at the beginning. The maximum
	// possible length keyId can take is preallocated (1 for length + 255 for
	// the actual keyId)
	const keyId = new Uint8Array(1 + 0xff);
	let state: (typeof DECRYPT_STATE)[keyof typeof DECRYPT_STATE] =
		DECRYPT_STATE.salt;

	const result = new TransformStream<BufferSource, ArrayBufferLike>({
		['start']: () => {
			// For decrypting, there are no actions that can be taken before
			// data are available.
		},
		['transform']: async (chunk, controller) => {
			const octets = sharedBufferToUint8Array(chunk);
			// Position within `chunk`
			let ipos = 0;
			while (ipos < chunk.byteLength) {
				switch (state) {
					// Starting point. Attempt to process the header, and the
					// salt (16 bytes) comes first.
					case DECRYPT_STATE.salt: {
						const subArray = octets.subarray(
							ipos,
							ipos + salt.byteLength - pos,
						);
						salt.set(subArray, pos);
						pos += subArray.byteLength;
						ipos += subArray.byteLength;
						if (pos === salt.byteLength) {
							pos = 0;
							state = DECRYPT_STATE.recordSize;
							continue;
						}
						break;
					}
					// After the salt, the record size (4 bytes) follows.
					case DECRYPT_STATE.recordSize: {
						const subArray = octets.subarray(ipos, ipos + 4 - pos);
						const recordSizeBuf = new ArrayBuffer(4);
						const recordSizeBufU8 = new Uint8Array(recordSizeBuf);
						const dataView = new DataView(recordSizeBuf);
						recordSizeBufU8.set(subArray, pos);
						recordSize |= dataView.getUint32(0, false);
						pos += subArray.byteLength;
						ipos += subArray.byteLength;
						if (pos === 4) {
							if (
								recordSize <= encoding.tag_length + 1 ||
								recordSize >
									(maxRecordSize == null
										? MAX_RECORD_SIZE
										: Math.min(
												MAX_RECORD_SIZE,
												maxRecordSize,
											))
							) {
								throw new RangeError(
									'Invalid record size: ' + recordSize,
								);
							}
							pos = 0;
							state = DECRYPT_STATE.keyIdLen;
							continue;
						}
						break;
					}
					// The single byte after the header denotes the key ID
					// length.
					// This is stored in the first position of `keyId`, which
					// is big enough for any possbile key ID.
					case DECRYPT_STATE.keyIdLen: {
						keyId[0] = octets[ipos++];
						state = DECRYPT_STATE.keyId;
						continue;
					}
					// Finally, read the key ID and store it in `keyId`.
					case DECRYPT_STATE.keyId: {
						const subArray = octets.subarray(
							ipos,
							ipos + keyId[0] - pos,
						);
						keyId.set(subArray, 1 + pos);
						pos += subArray.byteLength;
						ipos += subArray.byteLength;
						if (pos === keyId[0]) {
							const IKM = await lookupIKM(
								keyId.subarray(1, 1 + keyId[0]),
							);
							lookupIKM = void 0 as unknown as typeof lookupIKM;
							const initResult = await init(encoding, IKM, salt, [
								'decrypt',
							]);
							CEK = initResult[0];
							deriveNonce = initResult[1];
							buffer = new Uint8Array(recordSize);
							pos = 0;
							state = DECRYPT_STATE.payload;
							continue;
						}
						break;
					}
					// At this point, the header has been processed and there
					// remains only data to decrypt.
					case DECRYPT_STATE.payload: {
						const subArray = octets.subarray(
							ipos,
							ipos + recordSize - pos,
						);
						buffer.set(subArray, pos);
						pos += subArray.byteLength;
						ipos += subArray.byteLength;
						if (pos === recordSize) {
							const nonce = deriveNonce.next();
							const iv = nonce.value;
							const result = sharedBufferToUint8Array(
								await globalThis.crypto.subtle.decrypt(
									{
										['name']: encoding.params['name'],
										['iv']: iv,
										['tagLength']: encoding.tag_length << 3,
									},
									CEK,
									buffer.subarray(0, pos),
								),
							);
							// padding
							let i = result.byteLength - 1;
							for (; i > 0; i--) {
								if (result[i] !== 0) {
									break;
								}
							}
							if (result[i] === PADDING_DELIMITER_TERMINAL) {
								if (ipos !== chunk.byteLength) {
									throw new Error(
										'Unexpected terminal padding delimiter',
									);
								}
								state = DECRYPT_STATE.done;
							} else if (
								result[i] !== PADDING_DELIMITER_NONTERMINAL
							) {
								throw new Error('Invalid padding delimiter');
							}
							controller.enqueue(result.buffer.slice(0, i));
							result.fill(0);
							pos = 0;
							continue;
						}
						break;
					}
					// Any other state is invalid. If the state is
					// `DECRYPT_STATE.done`, it means that there were data
					// after the final record, which is not allowed.
					default: {
						throw new Error('Invalid state');
					}
				}
			}
		},
		['flush']: async (controller) => {
			switch (state) {
				// If the state is `DECRYPT_STATE.done`, there is nothing left
				// to do, as the last record has been processed.
				case DECRYPT_STATE.done: {
					return;
				}
				// If there state is `DECRYPT_STATE.payload`, then there must
				// be some data that still haven't been decrypted (the last)
				// record.
				case DECRYPT_STATE.payload: {
					if (pos < 1 + encoding.tag_length) {
						throw new Error('Unexpected end of data');
					}
					const nonce = deriveNonce.next();
					const iv = nonce.value;
					const result = sharedBufferToUint8Array(
						await globalThis.crypto.subtle.decrypt(
							{
								['name']: encoding.params['name'],
								['iv']: iv,
								['tagLength']: encoding.tag_length << 3,
							},
							CEK,
							buffer.subarray(0, pos),
						),
					);
					// padding
					let i = result.byteLength - 1;
					for (; i > 0; i--) {
						if (result[i] !== 0) {
							break;
						}
					}
					if (result[i] !== PADDING_DELIMITER_TERMINAL) {
						throw new Error(
							'Unexpected non-terminal padding delimiter',
						);
					}
					controller.enqueue(result.buffer.slice(0, i));
					result.fill(0);
					return;
				}
				// Any other state is invalid.
				default: {
					throw new Error('Invalid state');
				}
			}
		},
	});

	data.pipeThrough(result);

	return result.readable;
};

export default decrypt;
