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

const sharedBufferToUint8Array = <
	TB extends AllowSharedBufferSource,
	TL extends boolean,
	TR extends TB extends ArrayBuffer
		? ArrayBuffer
		: TL extends true
			? ArrayBuffer
			: TB extends ArrayBufferView<infer P>
				? P
				: never,
>(
	buf: TB,
	local?: TL,
): Uint8Array<TR> => {
	if (ArrayBuffer.isView(buf)) {
		const bufCopy =
			!local || buf.buffer instanceof ArrayBuffer
				? (buf.buffer as TR)
				: (buf.buffer.slice() as TR);
		return new Uint8Array(bufCopy).subarray(
			buf.byteOffset,
			buf.byteOffset + buf.byteLength,
		);
	}
	return new Uint8Array(buf) as Uint8Array<TR>;
};

export default sharedBufferToUint8Array;
