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

export type TEncoding = {
	params: AesKeyGenParams;
	cek_info: ArrayBufferLike;
	nonce_info: ArrayBufferLike;
	block_size: number;
	tag_length: number;
	nonce_length: number;
};

export const aes128gcm: Readonly<TEncoding> = {
	params: {
		['name']: 'AES-GCM',
		['length']: 128,
	},
	// The literal `Content-Encoding: aes128gcm\x00`
	get cek_info() {
		return new Uint8Array([
			0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x45, 0x6e, 0x63,
			0x6f, 0x64, 0x69, 0x6e, 0x67, 0x3a, 0x20, 0x61, 0x65, 0x73, 0x31,
			0x32, 0x38, 0x67, 0x63, 0x6d, 0x00,
		]);
	},
	// The literal `Content-Encoding: nonce\x00`
	get nonce_info() {
		return new Uint8Array([
			0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x45, 0x6e, 0x63,
			0x6f, 0x64, 0x69, 0x6e, 0x67, 0x3a, 0x20, 0x6e, 0x6f, 0x6e, 0x63,
			0x65, 0x00,
		]);
	},
	block_size: 16,
	tag_length: 16,
	nonce_length: 12,
};

// Non-standard
export const aes256gcm: Readonly<TEncoding> = {
	params: {
		['name']: 'AES-GCM',
		['length']: 256,
	},
	// The literal `Content-Encoding: aes256gcm\x00`
	get cek_info() {
		return new Uint8Array([
			0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x45, 0x6e, 0x63,
			0x6f, 0x64, 0x69, 0x6e, 0x67, 0x3a, 0x20, 0x61, 0x65, 0x73, 0x32,
			0x35, 0x36, 0x67, 0x63, 0x6d, 0x00,
		]);
	},
	// The literal `Content-Encoding: nonce\x00`
	get nonce_info() {
		return new Uint8Array([
			0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x45, 0x6e, 0x63,
			0x6f, 0x64, 0x69, 0x6e, 0x67, 0x3a, 0x20, 0x6e, 0x6f, 0x6e, 0x63,
			0x65, 0x00,
		]);
	},
	block_size: 16,
	tag_length: 16,
	nonce_length: 12,
};
