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

import type { TEncoding } from './encodings.js';

/**
 * Initialises the encrypt and decrypt processors by generating a
 * content-encryption key (CEK) from some Initial Keying Material (IKM) and
 * and a generator for nonce values.
 *
 * @async
 * @param encoding - The encoding details.
 * @param IKM - The Initial Keying Material.
 * @param salt - The salt value.
 * @param keyUsages - An array of valid key usages for the CEK.
 * @returns A promise that resolves to an array containing the derived CEK and a
 *   generator function for deriving nonces.
 */
const init = async (
	encoding: TEncoding,
	IKM: ArrayBufferLike,
	salt: ArrayBufferLike,
	keyUsages: KeyUsage[],
): Promise<
	[CEK: CryptoKey, deriveNonce: Generator<ArrayBuffer, never, never>]
> => {
	const PRK = await globalThis.crypto.subtle.importKey(
		'raw',
		IKM,
		'HKDF',
		false,
		['deriveKey', 'deriveBits'],
	);

	const CEK = await globalThis.crypto.subtle.deriveKey(
		{
			['name']: 'HKDF',
			['hash']: 'SHA-256',
			['info']: encoding.cek_info,
			['salt']: salt,
		},
		PRK,
		encoding.params,
		false,
		keyUsages,
	);

	const bits = await globalThis.crypto.subtle.deriveBits(
		{
			['name']: 'HKDF',
			['hash']: 'SHA-256',
			['info']: encoding.nonce_info,
			['salt']: salt,
		},
		PRK,
		encoding.nonce_length << 3,
	);

	// Devive a nonce that is (bits XOR sequence)
	// Currently, only nonces that are composed of whole 32-bit words
	// are supported.
	const deriveNonce = function* (): Generator<ArrayBuffer, never, never> {
		const sequence = new ArrayBuffer(encoding.nonce_length);
		const sequenceDataView = new DataView(sequence);
		const sequenceBuffer = new Uint8Array(sequence);

		const bitsBuffer = new Uint8Array(bits);

		// Maximum value for an individual counter (unsigned 32-bit)
		const seq_max = 0xffffffff;

		// Additional counters are needed if the nonce is longer than 32 bits
		const addtionalCountersLength = (encoding.nonce_length >> 2) - 1;
		const additionalCounters = new Array(addtionalCountersLength).fill(0);

		for (;;) {
			// Main loop: least significant counter
			for (let counter = 0; counter <= seq_max; counter++) {
				sequenceDataView.setUint32(
					sequenceDataView.byteLength - 4,
					counter,
					false,
				);

				const nonce = new Uint8Array(encoding.nonce_length);
				for (let l = 0; l < nonce.length; l++) {
					nonce[l] = bitsBuffer[l] ^ sequenceBuffer[l];
				}
				yield nonce;
			}

			// If the main loop ended, the additional counters need to be
			// updated accordingly
			for (let j = 0; j < addtionalCountersLength; j++) {
				// The last counter cannot be restarted
				if (
					j === addtionalCountersLength - 1 &&
					additionalCounters[j] === seq_max
				) {
					throw new RangeError('Maximum number of segments exceeded');
				}

				// Increase the current counter (wrapping around)
				additionalCounters[j] =
					(additionalCounters[j] + 1) % (seq_max + 1);
				sequenceDataView.setUint32(
					sequenceDataView.byteLength - 4 * (j + 2),
					additionalCounters[j],
					false,
				);
				// If the counter could be increased without it wrapping around,
				// the remainder should be left as they are.
				if (additionalCounters[j] !== 0) {
					break;
				}
			}
		}
	};

	return [CEK, deriveNonce()];
};

export default init;
