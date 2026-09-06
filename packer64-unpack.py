#!/usr/bin/env python
import argparse
import logging
import struct
import sys

KEY_SIZE = 128
SIZE_T = 8

_MINOFFSET = 2
_UNCONDITIONAL_MATCHLEN = 6
_UNCOMPRESSED_END = 4
_CWORD_LEN = 4


class HashDecompress:
	def __init__(self, pointers: int):
		self.offset = 0
		self.offset2 = [0] * pointers


class StateDecompress:
	def __init__(self, hash_values: int, pointers: int, stream_buffer_size: int):
		self.stream_buffer = bytearray(stream_buffer_size)
		self.stream_counter = 0

		self.hash = [HashDecompress(pointers) for _ in range(hash_values)]
		self.hash_counter = bytearray(hash_values)


def fast_read(source: bytearray, index: int) -> int:
	if index + 4 <= len(source):
		return int.from_bytes(source[index : index + 4], byteorder="little")
	return 0


def size_decompressed(source: bytearray) -> int:
	n = 4 if (source[0] & 2) == 2 else 1
	r = fast_read(source, 1 + n)
	return r & (0xFFFFFFFF >> ((4 - n) * 8))


def size_compressed(source: bytearray) -> int:
	n = 4 if (source[0] & 2) == 2 else 1
	r = fast_read(source, 1)
	return r & (0xFFFFFFFF >> ((4 - n) * 8))


def size_header(source: bytearray) -> int:
	return 2 * 4 + 1 if (source[0] & 2) == 2 else 2 * 1 + 1


def memcpy_up(
	destination: bytearray, dst_index: int, source: bytearray, src_index: int, n: int
) -> None:
	f = 0
	while f < n:
		destination[dst_index + f] = source[src_index + f]
		destination[dst_index + f + 1] = source[src_index + f + 1]
		destination[dst_index + f + 2] = source[src_index + f + 2]
		destination[dst_index + f + 3] = source[src_index + f + 3]
		f += _MINOFFSET + 1


class Qlz_LVL1_SB0:
	def __init__(self):
		self._POINTERS = 1
		self._HASH_VALUES = 4096

		self.state2 = StateDecompress(self._HASH_VALUES, self._POINTERS, 0)
		self.offset_base = 0

		self.reset_table_decompress()

	def reset_table_decompress(self) -> None:
		for i in range(self._HASH_VALUES):
			self.state2.hash_counter[i] = 0

	def hash_func(self, i: int) -> int:
		return ((i >> 12) ^ i) & (self._HASH_VALUES - 1)

	def hashat(self, source: bytearray, index: int) -> int:
		fetch = fast_read(source, index)
		return self.hash_func(fetch)

	def update_hash(self, source: bytearray, index: int) -> None:
		hash_val = self.hashat(source, index)
		self.state2.hash[hash_val].offset = index
		self.state2.hash_counter[hash_val] = 1

	def update_hash_upto(self, source: bytearray, lh: list[int], max_val: int):
		while lh[0] < max_val:
			lh[0] += 1
			self.update_hash(source, lh[0])

	def decompress(self, source: bytes | bytearray | list[int]) -> bytes:
		if not source:
			raise ValueError("Zero length buffer")

		if isinstance(source, (bytes, bytearray)) or (
			isinstance(source, list) and all(0 <= i <= 255 for i in source)
		):
			source = bytearray(source)
		else:
			raise TypeError(
				f"Source is {type(source)}, excpected bytes, bytearray or list[int]"
			)

		dsiz = size_decompressed(source)
		destination = bytearray(dsiz)

		if (source[0] & 1) == 1:
			self.reset_table_decompress()
			dsiz = self.decompress_core(source, 0, destination, 0, dsiz, 0)
		else:
			header_size = size_header(source)
			destination[:dsiz] = source[header_size : header_size + dsiz]
		self.state2.stream_counter = 0
		self.reset_table_decompress()

		return bytes(destination)

	def decompress_core(
		self,
		source: bytearray,
		src_index: int,
		destination: bytearray,
		dst_index: int,
		size: int,
		history: int,
	) -> int:
		src = size_header(source)
		dst = dst_index
		last_destination_byte = dst + size - 1
		cword_val = 1
		last_matchstart = (
			last_destination_byte - _UNCONDITIONAL_MATCHLEN - _UNCOMPRESSED_END
		)
		last_hashed = [dst_index - 1]
		last_source_byte = size_compressed(source) - 1
		bitlut = (4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0)

		while True:
			if cword_val == 1:
				if src + _CWORD_LEN - 1 > last_source_byte:
					return 0
				cword_val = fast_read(source, src)
				src += _CWORD_LEN

			if src + 4 - 1 > last_source_byte:
				return 0
			fetch = fast_read(source, src)

			if (cword_val & 1) == 1:
				matchlen = 0
				offset2 = 0

				cword_val >>= 1
				hash_val = (fetch >> 4) & 0xFFF
				offset2 = self.state2.hash[hash_val].offset
				if (fetch & 0xF) != 0:
					matchlen = (fetch & 0xF) + 2
					src += 2
				else:
					matchlen = source[src + 2]
					src += 3

				if offset2 < history or offset2 > dst - _MINOFFSET - 1:
					return 0
				if matchlen > last_destination_byte - dst - _UNCOMPRESSED_END + 1:
					return 0

				memcpy_up(destination, dst, destination, offset2, matchlen)
				dst += matchlen

				self.update_hash_upto(destination, last_hashed, dst - matchlen)
				last_hashed[0] = dst - 1
			else:
				if dst < last_matchstart:
					n = bitlut[cword_val & 0xF]
					memcpy_up(destination, dst, source, src, 4 - 1)
					cword_val >>= n
					dst += n
					src += n
					self.update_hash_upto(destination, last_hashed, dst - 3)
				else:
					while dst <= last_destination_byte:
						if cword_val == 1:
							src += _CWORD_LEN
							cword_val = 0x80000000
						if src >= last_source_byte + 1:
							return 0
						destination[dst] = source[src]
						dst += 1
						src += 1
						cword_val >>= 1
					self.update_hash_upto(
						destination, last_hashed, last_destination_byte - 3
					)
					return size


def parse_args():
	parser = argparse.ArgumentParser(
		description="Extract executable packed with Packer64."
	)
	parser.add_argument("input_file", help="input executable file to process")
	parser.add_argument(
		"-o", "--output", help="output script file (default: input_file.out)"
	)
	parser.add_argument("-v", "--verbose", action="store_true")
	args = parser.parse_args()
	return args


def rc4(data: bytes, key: bytes) -> bytes:
	S, j, out = list(range(256)), 0, []

	for i in range(256):
		j = (j + S[i] + key[i % len(key)]) % 256
		S[i], S[j] = S[j], S[i]

	i = j = 0
	for c in data:
		i = (i + 1) % 256
		j = (j + S[i]) % 256
		S[i], S[j] = S[j], S[i]
		out.append(c ^ S[(S[i] + S[j]) % 256])

	return bytes(out)


def main():
	args = parse_args()

	logging.addLevelName(logging.DEBUG, "\x1b[37m")
	logging.addLevelName(logging.INFO, "")

	if args.verbose:
		logging.basicConfig(
			format="%(levelname)s%(message)s\x1b[0m", level=logging.DEBUG
		)
	else:
		logging.basicConfig(
			format="%(levelname)s%(message)s\x1b[0m", level=logging.INFO
		)

	logging.info("Packer64 unpacker v1.0 - alol_re")
	logging.info(f"Unpacking {args.input_file}")

	with open(args.input_file, "rb") as f:
		data = f.read()

	data, payload_size = data[:-SIZE_T], int.from_bytes(
		data[-SIZE_T:], byteorder="little"
	)
	logging.debug(f"Found {payload_size=}")

	data, key = data[:-KEY_SIZE], data[-KEY_SIZE:]
	logging.debug(f"Found {key=}")

	payload = data[-payload_size + KEY_SIZE :]

	decrypted = rc4(payload, key)
	decompressed = Qlz_LVL1_SB0().decompress(decrypted)

	output_file = args.output or args.input_file + ".out"

	logging.info(f"Extracting to {output_file}")
	with open(output_file, "wb") as f:
		f.write(decompressed)


if __name__ == "__main__":
	main()
