rule R3C0NST_Gamaredon_Getimportbyhash : FILE
{
	meta:
		description = "Detects Gamaredon APIHashing"
		author = "Frank Boldewin (@r3c0nst)"
		id = "8f28273e-e8ca-52cb-8dbc-a235598b1975"
		date = "2021-05-12"
		modified = "2021-05-12"
		reference = "https://github.com/fboldewin/YARA-rules/"
		source_url = "https://github.com/fboldewin/YARA-rules//blob/54e9e6899b258b72074b2b4db6909257683240c2/APT.Gamaredon.GetImportByHash.yar#L1-L16"
		license_url = "N/A"
		logic_hash = "b3baebfb745ebc7b9e6df746bfa9622f925b8e8130932e44a148881e7d1fc162"
		score = 75
		quality = 90
		tags = "FILE"
		hash1 = "2d03a301bae0e95a355acd464afc77fde88dd00232aad6c8580b365f97f67a79"
		hash2 = "43d6e56515cca476f7279c3f276bf848da4bc13fd15fad9663b9e044970253e8"
		hash3 = "5c09f6ebb7243994ddc466058d5dc9920a5fced5e843200b1f057bda087b8ba6"

	strings:
		$ParseImgExportDir = { 8B 50 3C 03 D0 8B 52 78 03 D0 8B 4A 1C 03 C8 }
		$djb2Hashing = { 8B 75 08 BA 05 15 00 00 8B C2 C1 E2 05 03 D0 33 DB 8A 1E 03 D3 46 33 DB 8A 1E 85 DB 75 }

	condition:
		uint16(0)==0x5a4d and all of them
}