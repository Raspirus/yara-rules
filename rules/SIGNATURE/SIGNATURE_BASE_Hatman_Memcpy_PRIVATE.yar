rule SIGNATURE_BASE_Hatman_Memcpy_PRIVATE : HATMAN
{
	meta:
		description = "No description has been set in the source file - Signature Base"
		author = "Florian Roth"
		id = "2eb11f72-b37f-563f-8ce9-c4d4388598d3"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_hatman.yar#L29-L37"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "1e1566cc09e1ddd70cdb3b199f6972931f84a29ae2ef4815a5ecf1fe42afe42b"
		score = 75
		quality = 85
		tags = "HATMAN"

	strings:
		$memcpy_be = { 7c a9 03 a6  38 84 ff ff  38 63 ff ff  8c a4 00 01
                        9c a3 00 01  42 00 ff f8  4e 80 00 20              }
		$memcpy_le = { a6 03 a9 7c  ff ff 84 38  ff ff 63 38  01 00 a4 8c
                        01 00 a3 9c  f8 ff 00 42  20 00 80 4e              }

	condition:
		$memcpy_be or $memcpy_le
}