rule ARKBIRD_SOLG_APT_Puzzlemaker_Launcher_Jun_2021_1 : FILE
{
	meta:
		description = "Detect the launcher of the PuzzleMaker group"
		author = "Arkbird_SOLG"
		id = "ae31d9de-8e6c-5c1b-bc45-bc4e50cea00f"
		date = "2021-06-10"
		modified = "2021-11-01"
		reference = "https://securelist.com/puzzlemaker-chrome-zero-day-exploit-chain/102771/"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2021-06-09/PuzzleMaker/APT_PuzzleMaker_Launcher_Jun_2021_1.yara#L1-L19"
		license_url = "N/A"
		logic_hash = "5c717ca5c57a86e1b5db45b3d581a45be248d45820c00c40c57a001ac07ce1b2"
		score = 75
		quality = 75
		tags = "FILE"
		hash1 = "982f7c4700c75b81833d5d59ad29147c392b20c760fe36b200b541a0f841c8a9"
		tlp = "White"
		adversary = "PuzzleMaker"

	strings:
		$s1 = { 4c 89 6d bf 48 8d 45 bf 48 89 44 24 20 4c 8d 0d f9 45 01 00 33 d2 44 8d 42 01 48 8d 0d dc 45 01 00 ff 15 56 44 01 00 8b d8 85 c0 78 c6 4c 89 6d c7 48 8b 45 bf 48 8b 08 4c 8b 79 18 b9 18 00 00 00 e8 9b 04 00 00 48 8b d8 48 89 45 a7 48 85 c0 74 32 0f 57 c0 33 c0 0f 11 03 48 89 43 10 4c 89 6b 08 c7 43 10 01 00 00 00 48 8d 0d 15 fb 01 00 ff 15 cf 43 01 00 48 89 03 48 85 }
		$s2 = { 44 89 6c 24 38 4c 89 6c 24 30 c7 44 24 28 03 00 00 00 c7 44 24 20 03 00 00 00 45 33 c9 45 33 c0 41 8d 51 0a 48 8b 4d c7 ff 15 f6 42 01 00 85 c0 0f 88 bb 01 00 00 48 8d 0d 1d fa 01 00 ff 15 c1 42 01 00 4c 8b f8 48 8d 0d 1b fa 01 00 ff 15 b1 42 01 00 4c 8b e0 4c 89 6d df 48 8b 4d c7 48 8b 11 4c 8b 52 30 4c 89 6c 24 28 48 8d 45 df 48 89 44 24 20 45 33 c9 45 33 c0 49 8b d4 41 ff d2 4c 89 6d e7 48 8b 4d df 48 8b 01 4c 89 6c 24 20 4c 8d 4d e7 45 33 c0 49 8b d7 ff 90 98 00 00 00 4c 89 6d cf 48 8b 4d e7 48 8b 01 4c 8d 45 cf 33 d2 ff 50 78 b8 08 00 00 00 66 89 45 ef 8d 48 10 e8 dc 02 00 00 48 8b d8 48 89 45 a7 48 85 c0 74 33 0f 57 c0 33 c0 0f 11 03 48 89 43 10 4c 89 6b 08 c7 43 10 01 00 00 00 48 8b ce ff 15 14 42 01 00 48 89 03 48 85 c0 75 0e 48 85 }
		$s3 = { 4c 8d 05 75 0e 02 00 0f 1f 40 00 66 0f 1f 84 00 00 00 00 00 0f b6 d0 42 0f b6 0c 12 66 41 31 08 74 12 ff c0 49 83 c0 02 83 f8 20 72 e7 0f 1f 80 00 00 00 00 0f b7 05 49 09 02 00 48 8d 0d 76 09 02 00 66 d1 e8 66 83 e0 7f 66 0f 6f 15 f3 d4 01 00 66 89 05 2c 09 02 00 0f b7 05 27 09 02 00 66 d1 e8 66 83 e0 7f 66 89 05 19 09 02 00 0f b7 05 14 09 02 00 66 d1 e8 66 83 e0 7f 66 89 05 06 09 02 00 0f b7 05 01 09 02 00 66 d1 e8 66 83 e0 7f 66 89 05 f3 08 02 00 0f b7 05 ee 08 02 00 66 d1 e8 66 83 e0 7f 66 89 05 e0 08 02 00 0f b7 05 db 08 02 00 66 d1 e8 66 83 e0 7f 66 89 05 cd 08 02 00 0f b7 05 c8 08 02 00 66 d1 e8 66 83 e0 7f 66 89 05 ba 08 02 00 0f b7 05 b5 08 02 00 66 d1 e8 66 83 e0 7f f3 0f 6f 05 bc 08 02 00 66 89 05 9f 08 02 00 0f b7 05 9a 08 02 00 66 d1 e8 66 83 e0 7f 66 89 05 8c 08 02 00 0f b7 05 87 08 02 00 66 d1 e8 66 83 e0 7f 66 89 05 79 08 02 00 0f b7 05 74 08 02 00 66 d1 e8 66 83 e0 7f 66 89 05 66 08 02 00 0f b7 05 61 08 02 00 66 d1 e8 66 83 e0 7f 66 89 05 53 08 02 00 0f b7 05 4e 08 02 00 66 d1 e8 66 83 e0 7f 66 89 05 40 08 02 00 0f b7 05 3b 08 02 00 66 d1 e8 66 83 e0 7f 66 89 05 2d 08 02 00 0f b7 05 28 08 02 00 66 d1 e8 66 83 e0 7f 66 89 05 1a 08 02 00 0f b7 05 15 08 02 00 66 d1 e8 66 83 e0 7f 66 89 05 07 08 02 00 0f b7 05 02 08 02 00 66 d1 e8 66 83 e0 7f 66 89 05 f4 07 02 00 0f b7 05 ef 07 02 00 66 d1 e8 66 83 e0 7f 66 89 05 e1 07 02 00 b8 01 00 00 00 66 0f 6e c8 8d 50 05 66 0f d1 c1 66 0f db c2 f3 0f 7f 05 c7 07 02 00 0f }
		$s4 = { 48 89 9c 24 60 06 00 00 48 89 b4 24 68 06 00 00 48 89 bc 24 70 06 00 00 4c 89 b4 24 30 06 00 00 c7 05 2e 1a 02 00 04 00 00 00 48 c7 05 27 1a 02 00 01 00 00 00 4c 89 2d 2c 1a 02 00 ff 15 22 48 01 00 48 8d 35 8b 04 02 00 66 66 66 0f 1f 84 00 00 00 00 00 33 d2 44 89 6c 24 70 41 b8 08 03 00 00 48 8d 8d 10 02 00 00 45 8b f5 e8 e4 28 00 00 4c 8d 0d 5d 03 02 00 48 89 74 24 20 ba 84 01 00 00 48 8d 8d 10 02 00 00 49 c7 c0 ff ff ff ff e8 a0 fb ff ff 48 8d 54 24 70 48 8d 8d 10 02 00 00 e8 9f 05 00 00 8b d0 85 }
		$s5 = { 4c 89 6c 24 60 4c 8d 05 25 cc 01 00 4c 89 6c 24 58 48 8d 15 e1 04 02 00 4c 89 6c 24 50 41 b9 ff 01 0f 00 4c 89 6c 24 48 48 8b cf 4c 89 6c 24 40 48 89 74 24 38 44 89 6c 24 30 c7 44 24 28 02 00 00 00 c7 44 24 20 10 00 00 00 ff 15 19 46 01 00 48 8b d8 ff 15 a8 46 01 00 8b f0 48 85 db 74 22 48 8b cb ff 15 20 46 01 00 48 8b cb ff 15 ff 45 01 00 48 8b cf ff 15 f6 45 01 00 bf 01 00 00 }
		$s6 = { 33 d2 33 c9 41 b8 3f 00 0f 00 ff 15 f4 46 01 00 48 8b f8 48 85 }

	condition:
		uint16(0)==0x5a4d and filesize >80KB and 5 of ($s*)
}