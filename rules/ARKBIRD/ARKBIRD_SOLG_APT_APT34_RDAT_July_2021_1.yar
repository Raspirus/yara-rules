
rule ARKBIRD_SOLG_APT_APT34_RDAT_July_2021_1 : FILE
{
	meta:
		description = "Detect RDAT used by APT34"
		author = "Arkbird_SOLG"
		id = "136f8a9e-e680-5fab-8113-b4d33a47bc34"
		date = "2021-07-15"
		modified = "2021-07-16"
		reference = "https://twitter.com/ShadowChasing1/status/1415206437806960647"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2021-07-15/APT34/APT_APT34_RDAT_July_2021_1.yara#L1-L22"
		license_url = "N/A"
		logic_hash = "269788430ca8faff4b0ea5ec7c2a62f99f5f48ef3bc4ea3f7a27f1d735e64819"
		score = 75
		quality = 75
		tags = "FILE"
		hash1 = "b59dea96ef94e8d32ee1a1805174318643569bbdca0d7569ede19467ff09dcdc"
		hash2 = "65a6afc027ff851bd325d8a4f2ab4f326dd8f2c230bfd49a213c5afc00df8e2c"
		hash3 = "f9f6dbb09773f708b125a4cca509047eb33c8c53d9e15a8c41ae3d7a8c3e5c7c"
		tlp = "White"
		adversary = "APT34"

	strings:
		$s1 = { 0a 6f 70 74 20 25 6c 75 28 25 6c 75 29 20 73 74 61 74 20 25 6c 75 28 25 6c 75 29 20 73 74 6f 72 65 64 20 25 6c 75 20 6c 69 74 20 25 75 20 64 69 73 74 20 25 75 }
		$s2 = { 0a 6c 61 73 74 5f 6c 69 74 20 25 75 2c 20 6c 61 73 74 5f 64 69 73 74 20 25 75 2c 20 69 6e 20 25 6c 64 2c 20 6f 75 74 20 7e 25 6c 64 28 25 6c 64 25 25 29 }
		$s3 = { 70 65 6e 53 43 4d 61 6e 61 67 65 72 20 66 61 69 6c 65 64 20 28 25 64 29 0a }
		$s4 = { 43 72 65 61 74 65 53 65 72 76 69 63 65 20 66 61 69 6c 65 64 20 28 25 64 29 0a 00 00 00 00 00 00 53 65 72 76 69 63 65 20 69 6e 73 74 61 6c 6c 65 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79 0a }
		$s5 = { 49 8b cd ff 15 56 22 07 00 c6 05 87 7b 0a 00 00 c7 05 81 7b 0a 00 60 ea 00 00 49 83 c9 ff 45 33 c0 48 8d 55 20 48 8d 0d f3 7b 0a 00 e8 26 a4 ff ff 49 83 c9 ff 45 33 c0 48 8d 55 00 48 8d 0d bc 7b 0a 00 e8 0f a4 ff ff 41 b8 07 00 00 00 48 8d 15 92 b8 08 00 48 8d 0d 03 7c 0a 00 e8 16 a3 ff ff 49 83 c9 ff 45 33 c0 48 8d 55 40 48 8d 0d 6c 7b 0a 00 e8 df a3 ff ff 41 b8 ?? 00 00 00 48 8d 15 6a b8 08 00 48 8d 0d 13 7c 0a 00 e8 e6 a2 ff ff 48 8d 1d 0f 7d 0a 00 48 8b c3 48 83 3d 1c 7d 0a 00 08 48 0f 43 05 fc 7c 0a 00 48 89 44 24 58 48 8d 05 a0 03 00 00 48 89 44 24 60 48 89 7c 24 68 48 89 7c 24 70 48 8d 4c 24 58 ff 15 4e 21 07 00 85 c0 75 29 48 83 3d e2 7c 0a 00 08 48 0f 43 1d c2 7c 0a 00 48 8b d3 33 c9 ff 15 37 21 07 00 48 85 c0 74 09 48 8b c8 ff 15 f1 20 07 00 83 7c 24 30 02 7f 5d 48 8d 44 24 48 48 89 44 24 28 89 7c 24 20 45 33 c9 4c 8d 05 0a 71 ff ff 33 d2 33 c9 ff 15 60 22 07 00 48 8d 44 24 50 48 89 44 24 28 89 7c 24 20 45 33 c9 4c 8d 05 a8 95 ff ff 33 d2 33 c9 ff 15 3e 22 07 00 83 ca ff 48 8b c8 ff 15 f2 20 07 00 b9 64 00 00 00 ff 15 47 22 07 }
		$s6 = { 48 89 7d f0 48 89 7d f8 45 33 c0 33 d2 48 8d 4d e0 e8 43 a7 ff ff 41 b8 2c 00 00 00 48 8d 15 be bc 08 00 48 8d 4d e0 e8 ad a7 ff ff 48 89 7d 70 48 89 7d 78 45 33 c0 33 d2 48 8d 4d 60 e8 17 a7 ff ff 45 33 c0 48 8d 15 77 94 08 00 48 8d 4d 60 e8 84 a7 ff ff 83 7c 24 30 02 75 6e 48 8d 85 a8 00 00 00 48 89 85 a0 00 00 00 41 b8 03 00 00 00 49 8b 55 08 48 8d 8d a0 00 00 00 e8 c9 0a 00 00 48 8b 95 a0 00 00 00 48 8d 4d a0 e8 89 a5 ff ff 48 8d 85 a8 00 00 00 48 8b 8d a0 00 00 48 89 85 b0 10 00 00 48 8b da 48 8b f9 33 f6 89 74 24 78 c7 45 80 18 00 00 00 c7 45 90 01 00 00 00 48 89 75 88 45 33 c9 4c 8d 45 80 48 8d 54 24 68 48 8d 4c 24 60 ff 15 81 fe 06 00 45 33 c0 8d 56 01 48 8b 4c 24 60 ff 15 68 fe 06 00 45 33 c9 4c 8d 45 80 48 8d 54 24 70 48 8d 4c 24 58 ff 15 59 fe 06 00 45 33 c0 8d 56 01 48 8b 4c 24 58 ff 15 40 fe 06 00 33 c0 48 89 45 98 48 89 45 a0 48 89 45 a8 33 d2 44 8d 46 68 48 8d 4d c0 e8 ab 89 04 00 c7 45 c0 68 00 00 00 48 8b 44 24 68 48 89 45 20 48 8b 44 24 70 48 89 45 18 81 4d fc 00 01 00 00 48 8b d3 48 8d 4d 30 e8 bf fe ff ff 90 4c 8b c0 48 8d 8d 90 00 00 00 e8 9f 0d 00 00 90 45 33 c0 b2 01 48 8d 4d 30 e8 d0 7d ff ff 48 8d 95 90 00 00 00 48 83 bd a8 00 00 00 08 48 0f 43 95 90 00 00 00 48 8d 45 98 48 89 44 24 48 48 8d 45 c0 48 89 44 24 40 48 89 74 24 38 48 89 74 24 30 c7 44 24 28 00 00 00 08 c7 44 24 20 01 00 00 00 45 33 c9 45 33 c0 33 c9 ff 15 a7 fd 06 00 48 8b 4c 24 68 ff 15 94 fd 06 00 48 8b 4c 24 70 ff 15 89 fd 06 00 48 89 b5 80 00 00 00 48 89 b5 88 00 00 00 }

	condition:
		uint16(0)==0x5a4d and filesize >80KB and 5 of ($s*)
}