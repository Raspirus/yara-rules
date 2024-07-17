rule ARKBIRD_SOLG_RAN_ELF_Qnapcrypt_Aug_2021_2 : FILE
{
	meta:
		description = "Detect QNAPCrypt ransomware (x64 version)"
		author = "Arkbird_SOLG"
		id = "8cd54646-87da-5261-82f3-68ab96549379"
		date = "2021-08-11"
		modified = "2021-08-12"
		reference = "https://bazaar.abuse.ch/browse/tag/QNAPCrypt/"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2021-08-11/QNAPCrypt/RAN_ELF_QNAPCrypt_Aug_2021_2.yara#L1-L22"
		license_url = "N/A"
		logic_hash = "9eb3a499afbaaf2addb8ee12cc2d479ebbacd4d19cc270e995f12e83546008b4"
		score = 75
		quality = 73
		tags = "FILE"
		hash1 = "4829041c64971a0cb37d55e6ba83a57e01e76b26f3f744814b59bedbb3fefce8"
		hash2 = "50470f94e7d65b50bf00d7416a9634d9e4141c5109a78f5769e4204906ab5f0b"
		hash3 = "f9f5265f4c748ce0e2171915fb8edb6d967539ac46d624db8eb2586854dd0d9e"
		tlp = "white"
		adversary = "-"

	strings:
		$s1 = { 52 45 41 44 4d 45 5f 46 4f 52 5f 44 45 43 52 59 50 54 }
		$s2 = { 64 48 8b 0c 25 f8 ff ff ff 48 8d 44 24 ?? 48 3b 41 10 0f 86 [2] 00 00 48 81 ec ?? 00 00 00 48 89 ac 24 ?? 00 00 00 48 8d ac 24 ?? 00 00 00 48 8b 05 [3] 00 48 83 3d [3] 00 00 0f 86 [2] 00 00 48 8b 48 08 48 8b 00 48 89 04 24 48 89 4c 24 08 e8 [3] ff 48 c7 04 24 20 00 00 00 e8 [2] 00 00 48 c7 04 24 00 00 00 00 e8 [3] ff 48 8b 44 24 20 48 89 44 24 58 48 8b 4c 24 18 48 89 8c 24 88 00 00 00 48 8b 54 24 28 48 89 54 24 60 48 }
		$s3 = { 48 81 ec ?? 00 00 00 48 89 ac 24 ?? 00 00 00 48 8d ac 24 ?? 00 00 00 }
		$s4 = { 64 48 8b 0c 25 f8 ff ff ff 48 [0-5] 3b ?? 10 0f 86 [2] 00 00 48 ?? ec }
		$s5 = { 48 83 ec 78 48 89 6c 24 70 48 8d 6c 24 70 48 8b 05 [3] 00 48 8b 0d [3] 00 48 8b 15 [3] 00 48 89 0c 24 48 89 44 24 08 48 89 54 24 10 e8 [3] ff 48 8b 44 24 18 48 85 c0 0f 84 10 01 00 00 48 8b 48 28 48 8b 50 20 48 8b 40 18 48 89 04 24 48 89 54 24 08 48 89 4c 24 10 e8 [3] ff 48 8b 44 24 18 48 8b 4c 24 20 48 8b 54 24 28 48 8b 5c 24 30 48 85 d2 0f 85 a3 00 00 00 48 8d 15 [2] 03 00 48 39 d0 0f 85 13 01 00 00 48 8b 05 [3] 00 48 8b 15 [3] 00 48 89 04 24 48 89 54 24 08 48 89 4c 24 10 48 8b 84 24 80 00 00 00 48 89 44 24 18 48 8b 84 24 88 00 00 00 48 89 44 24 20 48 8b 84 24 90 00 00 00 48 89 44 24 28 e8 [3] ff 48 8b 44 24 38 48 8b 4c 24 40 48 8b 54 24 48 48 8b 5c 24 50 48 8b 74 24 30 48 89 b4 24 98 00 00 00 48 89 84 24 a0 00 00 00 48 89 8c 24 a8 00 00 00 48 89 94 24 b0 00 00 00 48 89 9c 24 b8 00 00 00 48 8b 6c 24 }
		$s6 = { 48 81 ec 48 01 00 00 48 89 ac 24 40 01 00 00 48 8d ac 24 40 01 00 00 48 8d 7c 24 38 48 8d 35 [2] 0f 00 48 89 6c 24 f0 48 8d 6c 24 f0 e8 [3] ff 48 8b 6d 00 48 8d 05 [2] 02 00 48 89 04 24 48 8b 84 24 50 01 00 00 48 89 44 24 08 48 89 44 24 10 e8 [3] ff 48 8b 44 24 18 48 89 84 24 38 01 00 00 31 c9 eb 18 8b 54 84 38 48 8b 5c 24 30 48 8b 84 24 38 01 00 00 89 14 98 48 8d 4b 01 48 8b 94 24 50 01 00 00 48 39 d1 7d 2c 48 89 4c 24 30 90 48 8b 05 [3] 00 48 89 04 24 48 c7 44 24 08 40 00 00 00 e8 [3] ff 48 8b 44 24 10 48 83 f8 40 72 b1 eb 46 48 c7 04 24 00 00 00 00 48 89 44 24 08 48 89 54 24 10 48 89 54 24 18 e8 [3] ff 48 8b 44 24 28 48 8b 4c 24 20 48 89 8c 24 58 01 00 00 48 89 84 24 60 01 00 00 48 8b ac 24 40 01 00 }

	condition:
		uint32(0)==0x464C457F and filesize >25KB and all of ($s*)
}