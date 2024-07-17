
rule ARKBIRD_SOLG_RAN_Haron_Aug_2021_1 : FILE
{
	meta:
		description = "Detect Haron locker"
		author = "Arkbird_SOLG"
		id = "5900ad0e-66ca-5127-b8c2-cc23ace8929f"
		date = "2021-08-09"
		modified = "2021-08-09"
		reference = "Internal Research"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2021-08-09/RAN_Haron_Aug_2021_1.yara#L1-L22"
		license_url = "N/A"
		logic_hash = "5001041d9bb8acc0fa5e0e3b4cfacc5a891bed6885101ae3513b5524c91c572d"
		score = 75
		quality = 75
		tags = "FILE"
		hash1 = "66ed5384220ff3091903e14a54849f824fdd13ac70dc4e0127eb59c1de801fc2"
		hash2 = "6e6b78a1df17d6718daa857827a2a364b7627d9bfd6672406ad72b276014209c"
		tlp = "white"
		adversary = "Haron"

	strings:
		$s1 = { 02 17 8d ?? 00 00 01 [2] 16 20 [2] 00 00 20 00 ?? 00 00 [1-5] 73 [2] 01 00 0a a2 ?? 7d ?? 01 00 0a }
		$s2 = { 03 7e ?? 00 00 04 20 [2] 66 06 28 [2] 00 06 28 ?? 00 00 06 }
		$s3 = { 1f 38 16 02 28 ?? 01 00 0a 16 9a 6f ?? 01 00 0a b8 28 ?? 00 00 06 13 07 7e ?? 01 00 0a 13 0b 11 07 11 0b 11 06 6e 1f 60 6a d7 88 20 00 30 00 00 1f 40 28 ?? 00 00 06 28 ?? 01 00 0a b8 13 08 11 07 02 7e ?? 00 00 04 20 [2] 66 06 28 [2] 00 06 28 ?? 00 00 06 28 ?? 01 00 0a b8 7e ?? 00 00 04 20 [2] 66 06 28 [2] 00 06 28 ?? 00 00 06 84 b8 13 09 11 07 02 7e }
		$s4 = { 1f 18 02 28 ?? 01 00 0a 16 9a 6f ?? 01 00 0a b8 28 ?? 00 00 06 0a 7e ?? 01 00 0a 0b 06 07 28 ?? 01 00 0a 0c 08 2c 04 07 0d 2b 6f 12 04 fe 15 ?? 00 00 02 12 04 11 04 28 ?? 00 00 2b b8 7d ?? 00 00 04 06 12 04 28 ?? 00 00 06 0c 08 2c 4a 12 04 7c ?? 00 00 04 28 ?? 01 00 0a 20 ff ff ff 7f 6a fe 02 16 fe 01 13 05 11 05 2c 17 03 12 04 7b ?? 00 00 04 17 28 ?? 01 00 0a 16 fe 01 13 06 11 06 2d 0c 06 12 04 28 ?? 00 00 06 2d c2 2b 0a 12 04 7b ?? 00 00 04 0d 09 2a 07 0d 09 2a }
		$s5 = { 28 0e 00 00 0a 0b 16 0c 38 84 01 00 00 07 08 9a 0a 06 6f ?? 01 00 0a 20 00 00 80 0c 6a 3e 66 01 00 00 06 6f 0d 00 00 0a 28 0c 00 00 0a 6f 0d 00 00 0a 28 21 00 00 0a 39 4c 01 00 00 06 6f 0d 00 00 0a 7e ?? 00 00 04 20 [2] 66 06 28 [2] 00 06 6f 2e 00 00 0a 3a 2d 01 00 00 06 6f 0d 00 00 0a 7e ?? 00 00 04 20 [2] 66 06 28 [2] 00 06 6f 2e 00 00 0a 3a 0e 01 00 00 06 6f 0d 00 00 0a 7e ?? 00 00 04 20 [2] 66 06 28 [2] 00 06 6f 2e 00 00 0a 3a ef 00 00 00 06 6f 0d 00 00 0a 7e ?? 00 00 04 20 [2] 66 06 28 [2] 00 06 6f 2e 00 00 0a 3a d0 00 00 00 06 6f 0d 00 00 0a 7e ?? 00 00 04 20 [2] 66 06 28 [2] 00 06 6f 2e 00 00 0a 3a b1 00 00 00 06 6f 0d 00 00 0a 7e ?? 00 00 04 20 [2] 66 06 28 [2] 00 06 6f 2e 00 00 0a 3a 92 00 00 00 06 6f 0d 00 00 0a 7e ?? 00 00 04 20 [2] 66 06 28 [2] 00 06 6f 2e 00 00 0a 2d 76 06 6f 0d 00 00 0a 7e ?? 00 00 04 20 [2] 66 06 28 [2] 00 06 6f 2e 00 00 0a 2d 5a 06 6f 0d 00 00 0a 7e ?? 00 00 04 20 [2] 66 06 28 [2] 00 06 6f 2e 00 00 0a 2d 3e 06 6f 0d 00 00 0a 7e ?? 00 00 04 20 [2] 66 06 28 [2] 00 06 6f 2e 00 00 0a 2d 22 06 6f 0d 00 00 0a 7e ?? 00 00 04 20 [2] 66 06 28 [2] 00 06 6f 2e 00 00 0a 2d 06 06 6f 26 00 00 0a de 03 26 de 00 08 17 58 0c 08 07 8e 69 3f 73 fe ff ff 20 c4 09 00 00 28 18 00 00 0a dd 57 fe ff ff 26 dd 51 fe ff ff }
		$s6 = { 7e ?? 00 00 0a 7e ?? 00 00 04 20 [2] 66 06 28 [2] 00 06 28 09 00 00 06 6f [2] 00 0a 0a 06 7e ?? 00 00 04 20 [2] 66 06 28 [2] 00 06 28 09 00 00 06 7e ?? 00 00 04 20 [2] 66 06 28 [2] 00 06 6f [2] 00 0a 06 6f ?? 00 00 0a de 03 26 de 00 2a }
		$s7 = { 28 ?? 00 00 06 0a 02 06 28 ?? 00 00 06 0b 07 6f [2] 00 0a 16 16 17 20 ff 0f 1f 00 17 14 73 [2] 00 0a 16 14 73 [2] 00 0a 6f [2] 00 0a 02 06 07 28 ?? 00 00 06 de 03 26 de 00 2a 00 00 00 }

	condition:
		uint16(0)==0x5A4D and filesize >25KB and 6 of ($s*)
}