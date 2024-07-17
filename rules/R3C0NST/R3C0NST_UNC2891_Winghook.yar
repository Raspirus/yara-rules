rule R3C0NST_UNC2891_Winghook : FILE
{
	meta:
		description = "Detects UNC2891 Winghook Keylogger"
		author = "Frank Boldewin (@r3c0nst)"
		id = "e5955fa0-8204-58e3-88a6-de4b47756ede"
		date = "2022-03-30"
		modified = "2023-01-05"
		reference = "https://github.com/fboldewin/YARA-rules/"
		source_url = "https://github.com/fboldewin/YARA-rules//blob/54e9e6899b258b72074b2b4db6909257683240c2/UNC2891_Winghook.yar#L1-L17"
		license_url = "N/A"
		logic_hash = "b821d0809a91c54d06764f5a04c458ec7190b41823b2fe65d198342715f22050"
		score = 75
		quality = 90
		tags = "FILE"
		hash1 = "d071ee723982cf53e4bce89f3de5a8ef1853457b21bffdae387c4c2bd160a38e"

	strings:
		$code1 = {01 F9 81 E1 FF 00 00 00 41 89 CA [15] 44 01 CF 81 E7 FF 00 00 00}
		$code2 = {83 E2 0F 0F B6 14 1? 32 14 01 88 14 0? 48 83 ?? ?? 48 83 ?? ?? 75}
		$str1 = "fgets" ascii
		$str2 = "read" ascii

	condition:
		uint32(0)==0x464c457f and filesize <100KB and 1 of ($code*) and all of ($str*)
}