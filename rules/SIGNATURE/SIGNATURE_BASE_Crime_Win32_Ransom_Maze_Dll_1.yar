rule SIGNATURE_BASE_Crime_Win32_Ransom_Maze_Dll_1 : FILE
{
	meta:
		description = "Detects Maze ransomware payload dll unpacked"
		author = "@VK_Intel"
		id = "873aea2b-2dd4-5682-b979-35e73fbc189f"
		date = "2020-04-18"
		modified = "2023-12-05"
		reference = "https://twitter.com/VK_Intel/status/1251388507219726338"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/crime_maze_ransomware.yar#L1-L17"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "5b76636c05141687fa5cc507ac67d6a5d1f6c89166fd302e94fe61b412451159"
		score = 75
		quality = 85
		tags = "FILE"
		tlp = "white"

	strings:
		$str1 = "Maze Ransomware" wide
		$str2 = "--logging" wide
		$str3 = "DECRYPT-FILES.txt" wide
		$tick_server_call = { ff ?? ?? 8b ?? ?? ?? ?? ?? ff d6 8b ?? 89 f9 50 ff ?? ?? ff d6 8d ?? ?? ?? 89 ?? ?? ?? 56 e8 ?? ?? ?? ?? 83 c4 04 b9 67 66 66 66 89 c5 f7 e9 89 d0 d1 fa c1 e8 1f 01 c2 8d ?? ?? 29 c5 56 e8 ?? ?? ?? ?? 83 c4 04 b9 56 55 55 55 89 c6 f7 e9 89 f9 89 d0 c1 e8 1f 01 d0 8d ?? ?? 29 c6 8b ?? 55 56 ff ?? ?? 85 c0 0f ?? ?? ?? ?? ?? 89 ?? ?? ?? 8b ?? ?? ?? ?? ?? 89 c5 50 ff d3 89 c6 ff ?? ?? ?? ff d3 8b ?? ?? ?? 01 f0 3d ff 03 00 00 0f ?? ?? ?? ?? ?? 55 ff ?? ?? ?? 68 a2 95 c3 00 53 ff ?? ?? ?? ?? ?? 83 c4 10 c6 ?? ?? ?? c6 ?? ?? ?? ?? }

	condition:
		( uint16(0)==0x5a4d and 3 of them ) or all of them
}