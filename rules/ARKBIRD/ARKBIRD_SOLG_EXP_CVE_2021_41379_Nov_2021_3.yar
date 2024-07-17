
rule ARKBIRD_SOLG_EXP_CVE_2021_41379_Nov_2021_3 : CVE_2021_41379 FILE
{
	meta:
		description = "Detect exploit tool using CVE-2021-41379 (variant 3)"
		author = "Arkbird_SOLG"
		id = "c82578d6-63ca-50f6-b105-321791ec8808"
		date = "2021-11-26"
		modified = "2021-11-29"
		reference = "Internal Research"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2021-11-26/EXP_CVE_2021_41379_Nov_2021_3.yara#L1-L27"
		license_url = "N/A"
		logic_hash = "559c4ca0e9ac60e3dd7d5b9a8eb22d887b0b436d4e1fc528e05e7a33ecce0aa6"
		score = 75
		quality = 75
		tags = "CVE-2021-41379, FILE"
		hash1 = "0dcda614c0128813bf74802f0e98ffd5ec32a40f35ed42778a5ec5984b5adf47"
		hash2 = "3c78e07924e1503be1f8785c23d0dd813f04211992cbd6a4955cd0e25c745735"
		hash3 = "57ec6e15bcc9c79c118f97103815bd74226d4baae334142890a52fbbc5006f1b"
		hash4 = "9d24383e50e61257c565e47ec073cbb2cd751b6f650f0d542b0643dbe6691b3c"
		tlp = "white"
		adversary = "-"

	strings:
		$s1 = { 8d 0d [2] 03 00 e8 [2] ff ff 41 b8 00 00 00 80 33 d2 33 c9 ff 15 [2] 03 00 48 89 45 08 41 b8 01 00 00 00 48 8d 15 [3] 00 48 8b 4d 08 ff 15 [2] 03 00 48 89 45 28 ff 15 [2] 03 00 3d 24 }
		$s2 = { 33 d2 48 8b 4d 08 ff 15 [2] 03 00 c7 45 24 00 00 00 00 48 8d 55 24 48 8b 4d 08 ff 15 [2] 03 00 48 8b 4d 08 ff 15 [2] 03 00 ff 15 [2] 03 00 44 8b c0 33 d2 b9 00 10 10 00 ff 15 [2] 03 00 48 89 45 48 48 c7 45 68 00 00 00 00 4c 8d 45 68 ba ff 01 0f 00 48 8b 4d 48 ff 15 [2] 03 00 48 8b 4d 48 ff 15 [2] 03 00 48 c7 85 88 00 00 00 00 00 00 00 48 8d 85 88 00 00 00 48 89 44 24 28 c7 44 24 20 01 00 00 00 41 b9 02 00 00 00 45 33 c0 ba ff 01 0f 00 48 8b 4d 68 ff 15 [2] 03 00 48 8b 4d 68 ff 15 [2] 03 00 41 b9 04 00 00 00 4c 8d 45 24 ba 0c 00 00 00 48 8b 8d 88 00 00 00 ff 15 [2] 03 00 48 8d 85 a8 00 00 00 48 8b f8 33 c0 b9 18 00 00 00 f3 aa 48 8d 85 e0 00 00 00 48 8b f8 33 c0 b9 68 00 00 00 f3 aa c7 85 e0 00 00 00 68 00 00 00 b8 05 00 00 00 66 89 85 20 01 00 00 48 8d 05 [2] 02 00 48 89 85 f0 00 00 00 41 b8 04 01 00 00 48 8d 95 70 01 00 00 48 8d 0d [2] 02 00 ff 15 [2] 03 00 48 8d 85 a8 00 00 00 48 89 44 24 50 48 8d 85 e0 00 00 00 48 89 44 24 48 48 c7 44 24 40 00 00 00 00 48 c7 44 24 38 00 00 00 00 c7 44 24 30 10 00 00 00 c7 44 24 28 00 00 00 00 48 c7 44 24 20 00 00 00 00 45 33 c9 45 33 c0 48 8d 95 70 01 00 00 48 8b 8d 88 00 00 00 ff 15 [2] 03 00 48 8b 8d 88 00 00 00 ff 15 [2] 03 00 48 8b 8d a8 00 00 00 ff 15 [2] 03 00 48 8b 8d b0 00 00 00 ff 15 [2] 03 00 }
		$s3 = { 41 b8 00 00 00 80 33 d2 33 c9 ff 15 [2] 03 00 48 89 45 08 41 b8 01 00 00 00 48 8d 15 [3] 00 48 8b 4d 08 ff 15 [2] 03 00 48 89 45 28 48 8b 4d 08 ff 15 [2] 03 00 48 c7 45 48 00 00 00 00 c7 45 64 00 00 00 00 4c 8d 4d 64 45 33 c0 48 8b 55 48 48 8b 4d 28 ff 15 [2] 03 00 8b 45 64 48 89 85 88 04 00 00 ff 15 [2] 03 00 48 8b 8d 88 04 00 00 4c 8b c1 ba 0c 00 00 00 48 8b c8 ff 15 [2] 03 00 48 89 45 48 4c 8d 4d 64 44 8b 45 64 48 8b 55 48 48 8b 4d 28 ff 15 [2] 03 00 48 8b 45 48 4c 8b 40 10 ba 04 01 00 00 48 8d 8d 90 00 00 00 ff 15 [2] 03 00 ff 15 [2] 03 00 4c 8b 45 48 33 d2 48 8b c8 ff 15 [2] 03 00 48 8b 4d 28 ff 15 [2] 03 00 c7 85 b4 02 00 00 01 00 00 00 c7 85 d4 02 00 00 00 00 00 }
		$s4 = { 68 00 00 00 80 6a 00 6a 00 ff 15 24 f0 43 00 3b f4 e8 bf 5b ff ff 89 45 f8 8b f4 6a 01 68 34 84 43 00 8b 45 f8 50 ff 15 20 f0 43 00 3b f4 e8 a2 5b ff ff 89 45 ec 8b f4 ff 15 2c f1 43 00 3b f4 e8 90 5b ff ff 3d 24 }
		$s5 = { f3 ab a1 0c d0 43 00 33 c5 89 45 fc b9 d9 10 44 00 e8 55 9c ff ff 8b 45 08 89 45 f4 b9 0c 00 00 00 be a4 7e 43 00 8d bd ec f7 ff ff f3 a5 68 d0 07 00 00 6a 00 8d 85 1c f8 ff ff 50 e8 bd 95 ff }
		$s6 = { 8b f4 6a 00 8b 45 f4 50 ff 15 88 f0 43 00 3b f4 e8 8d 67 ff ff c7 45 e8 00 00 00 00 8b f4 8d 45 e8 50 8b 4d f4 51 ff 15 c8 f0 43 00 3b f4 e8 6f 67 ff ff 8b f4 8b 45 f4 50 ff 15 30 f1 43 00 3b f4 e8 5c 67 ff ff 8b f4 ff 15 a4 f0 43 00 3b f4 e8 4d 67 ff ff 8b f4 50 6a 00 68 00 10 10 00 ff 15 b8 f0 43 00 3b f4 e8 36 67 ff ff 89 45 dc c7 45 d0 00 00 00 00 8b f4 8d 45 d0 50 68 ff 01 0f 00 8b 4d dc 51 ff 15 3c f0 43 00 3b f4 e8 10 67 ff ff 8b f4 8b 45 dc 50 ff 15 30 f1 43 00 3b f4 e8 fd 66 ff ff c7 45 c4 00 00 00 00 8b f4 8d 45 c4 50 6a 01 6a 02 6a 00 68 ff 01 0f 00 8b 4d d0 51 ff 15 38 f0 43 00 3b f4 e8 d4 66 ff ff 8b f4 8b 45 d0 50 ff 15 30 f1 43 00 3b f4 e8 c1 66 ff ff 8b f4 6a 04 8d 45 e8 50 6a 0c 8b 4d c4 51 ff 15 2c f0 43 00 3b f4 e8 a6 66 ff ff 33 c0 89 45 ac 89 45 b0 89 45 b4 89 45 b8 6a 44 6a 00 8d 85 60 ff ff ff 50 e8 36 63 ff ff 83 c4 0c c7 85 60 ff ff ff 44 00 00 00 b8 05 00 00 00 66 89 45 90 c7 85 68 ff ff ff a0 86 43 00 8b f4 68 04 01 00 00 8d 85 50 fd ff ff 50 68 c8 86 43 00 ff 15 58 f1 43 00 3b f4 e8 48 66 ff ff 8b f4 8d 45 ac 50 8d 8d }
		$s7 = { 40 53 48 81 ec 30 08 00 00 48 8b 05 b8 78 00 00 48 33 c4 48 89 84 24 20 08 00 00 0f 10 05 7e 4e 00 00 48 8b d9 33 d2 0f 10 0d 82 4e 00 00 48 8d 4c 24 50 41 b8 d0 07 00 00 0f 29 44 24 20 0f 10 05 7b 4e 00 00 0f 29 4c 24 30 0f 29 44 24 40 e8 da 42 00 00 4c 8b 03 48 8d 4c 24 20 ba 00 04 00 00 e8 6a f8 ff ff 33 d2 8d 4a 02 ff 15 77 4c 00 00 48 8b 4b 08 48 8d 54 24 20 ff 15 70 4c 00 00 33 c0 48 8b 8c 24 20 08 00 00 48 33 cc e8 de 34 00 00 48 81 c4 30 08 00 00 }
		$s8 = { 33 d2 48 8b cb ff 15 c6 2c 00 00 83 65 00 00 48 8d 55 00 48 8b cb ff 15 85 2c 00 00 48 8b cb ff 15 1c 2d 00 00 ff 15 86 2c 00 00 33 d2 b9 00 10 10 00 44 8b c0 ff 15 46 2c 00 00 48 83 64 24 68 00 4c 8d 44 24 68 48 8b c8 ba ff 01 0f 00 48 8b d8 ff 15 82 2b 00 00 48 8b cb ff 15 e1 2c 00 00 48 8b 4c 24 68 48 8d 44 24 60 48 83 64 24 60 00 41 b9 02 00 00 00 48 89 44 24 28 45 33 c0 ba ff 01 0f 00 c7 44 24 20 01 00 00 00 ff 15 80 2b 00 00 48 8b 4c 24 68 ff 15 a5 2c 00 00 48 8b 4c 24 60 4c 8d 45 00 41 b9 04 00 00 00 41 8d 51 08 ff 15 1c 2b 00 00 33 c0 48 8d 4d 90 0f 57 c0 48 89 45 80 33 d2 0f 11 44 24 70 8d 58 68 44 8b c3 e8 5b 25 00 00 8d 43 9d 89 5d 90 66 89 45 d0 48 8d 55 10 48 8d 05 e0 33 00 00 41 b8 04 01 00 00 48 8d 0d f3 33 00 00 48 89 45 a0 ff 15 91 2c 00 00 48 8b 4c 24 60 48 8d 44 24 70 48 89 44 24 50 48 8d 55 10 48 8d 45 90 45 33 c9 48 89 44 24 48 45 33 c0 48 83 64 24 40 00 48 83 64 24 38 00 c7 44 24 30 10 00 00 00 83 64 24 28 00 48 83 64 24 20 00 ff 15 9a 2a 00 00 48 8b 4c 24 60 ff 15 ef 2b 00 00 48 8b 4c 24 70 ff 15 e4 2b 00 00 48 8b 4c 24 78 ff 15 d9 }
		$s9 = { 33 d2 33 c9 41 b8 00 00 00 80 ff 15 ba 33 00 00 41 b8 01 00 00 00 48 8d 15 7d 3b 00 00 48 8b c8 48 8b d8 ff 15 d9 33 00 00 48 8b cb 48 8b f8 ff 15 8d 33 00 00 4c 8d 4c 24 20 89 74 24 20 45 33 c0 33 d2 48 8b cf ff 15 ae 33 00 00 8b 5c 24 20 ff 15 64 34 00 00 44 8b c3 ba 0c 00 00 00 48 8b c8 ff 15 33 34 00 00 44 8b 44 24 20 4c 8d 4c 24 20 48 8b d0 48 8b cf 48 8b d8 ff 15 7a 33 00 00 4c 8b 43 10 48 8d 4c 24 30 ba 04 01 00 00 ff 15 46 37 00 00 ff 15 20 34 00 00 4c 8b c3 33 d2 48 8b c8 ff 15 9a 33 00 00 48 8b cf ff 15 11 33 00 00 48 8d 4c 24 30 8b fe ff 15 a4 33 00 00 83 e8 02 }

	condition:
		uint16(0)==0x5A4D and filesize >25KB and 3 of ($s*)
}