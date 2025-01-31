from random import randint
from unittest import TestCase
from unittest.mock import patch

from mlkem.auxiliary.general import (
    bits_to_bytes,
    byte_decode,
    byte_encode,
    bytes_to_bits,
    compress,
    decompress,
)
from mlkem.math.constants import n, q
from mlkem.math.field import Zm

from parameterized import parameterized  # type: ignore


class TestGeneral(TestCase):
    @parameterized.expand(
        [
            ([0, 0, 0, 0, 0, 0, 0, 0], [0]),
            ([1, 0, 0, 0, 0, 0, 0, 0], [1]),
            ([0, 0, 0, 0, 0, 0, 0, 1], [128]),
            ([1, 1, 0, 1, 0, 0, 0, 1], [139]),
            ([1, 1, 1, 1, 1, 1, 1, 1], [255]),
            ([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], [1, 128]),
            ([0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0], [128, 1]),
        ]
    )
    def test_bits_to_bytes(self, bits: list[int], expected: list[int]) -> None:
        actual = bits_to_bytes(bits)
        self.assertEqual(expected, actual)

    @parameterized.expand(
        [
            ([0], [0, 0, 0, 0, 0, 0, 0, 0]),
            ([1], [1, 0, 0, 0, 0, 0, 0, 0]),
            ([128], [0, 0, 0, 0, 0, 0, 0, 1]),
            ([139], [1, 1, 0, 1, 0, 0, 0, 1]),
            ([255], [1, 1, 1, 1, 1, 1, 1, 1]),
            ([1, 128], [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            ([128, 1], [0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0]),
        ]
    )
    def test_bytes_to_bits(self, byts: list[int], expected: list[int]) -> None:
        actual = bytes_to_bits(byts)
        self.assertEqual(expected, actual)

    def test_bytes_to_bits_random(self) -> None:
        random_tests = 25

        for _ in range(random_tests):
            expected = [randint(0, 255) for _ in range(randint(1, 5))]
            bits = bytes_to_bits(expected)

            actual = bits_to_bytes(bits)
            self.assertEqual(expected, actual)

    def test_decompress_compress(self) -> None:
        random_tests = 25

        for _ in range(random_tests):
            d = randint(1, 11)
            val = randint(0, (1 << d) - 1)
            y = Zm(val, 1 << d)

            actual = compress(d, decompress(d, y))
            self.assertEqual(y, actual)

    @patch(
        "mlkem.auxiliary.general.n", 4
    )  # patch n to a smaller, more manageable, size
    def test_byte_encode_zq(self) -> None:
        # Field elements in little-endian binary
        # [(000000001011), (000000000000), (000101111100), (111111110000)]
        f = [Zm(3328, q), Zm(0, q), Zm(1000, q), Zm(255, q)]

        # Little-endian binary to bytes
        # 00000000 = 0x00, 10110000 = 0x0d, 00000000 = 0x00, 00010111 = 0xe8, 11001111 = 0xf3, 11110000 = 0x0f
        expected = b"\x00\x0d\x00\xe8\xf3\x0f"

        actual = byte_encode(12, f)

        self.assertEqual(expected, actual)

    @patch(
        "mlkem.auxiliary.general.n", 4
    )  # patch n to a smaller, more manageable, size
    def test_byte_decode_zq(self) -> None:
        # bytes in little-endian binary
        # 00000000 = 0x00, 10110000 = 0x0d, 00000000 = 0x00, 00010111 = 0xe8, 11001111 = 0xf3, 11110000 = 0x0f
        b = b"\x00\x0d\x00\xe8\xf3\x0f"

        # Little-endian binary to field elements
        # [(000000001011), (000000000000), (000101111100), (111111110000)]
        expected = [Zm(3328, q), Zm(0, q), Zm(1000, q), Zm(255, q)]

        actual = byte_decode(12, b)

        self.assertEqual(expected, actual)

    def test_encode_decode(self) -> None:
        random_tests = 25

        for _ in range(random_tests):
            f = [Zm(randint(0, 1 << 12), q) for _ in range(n)]

            encoded = byte_encode(12, f)
            actual = byte_decode(12, encoded)

            self.assertEqual(f, actual)
