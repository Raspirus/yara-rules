
rule RUSSIANPANDA_Win_Mal_Mpxdropper : FILE
{
	meta:
		description = "Detects MpxDropper"
		author = "RussianPanda"
		id = "26ee0a12-c727-5953-8ebb-dd8a8d772561"
		date = "2024-03-01"
		modified = "2024-03-01"
		reference = "https://github.com/RussianPanda95/Yara-Rules"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/c65f3c62711bf141e4eb926ffe3a9880e5331974/MpxDropper/mal_win_MpxDropper.yar#L1-L11"
		license_url = "N/A"
		hash = "3a44a45afbfe5fc7cdeb3723e05c4e892b079abdb7d1e8d6fc70496ef0a14d5d"
		logic_hash = "e8d2672553c7f44e1cc177fad6596bd58b5c32a7541f91ce1207e6b21ef6e52d"
		score = 75
		quality = 83
		tags = "FILE"

	strings:
		$s1 = {43 3a 5c 55 73 65 72 73 5c 6d 70 78 31 36 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73}

	condition:
		uint16(0)==0x5A4D and all of them
}