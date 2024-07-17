
rule DITEKSHEN_INDICATOR_KB_LNK_BOI_MAC : FILE
{
	meta:
		description = "Detects Windows Shortcut .lnk files with previously known bad Birth Object ID and MAC address combination"
		author = "ditekSHen"
		id = "bfef07dc-a368-5119-82dd-de2096b17dd1"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_knownbad_id.yar#L605-L637"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "31a7966a0ea0fca363d2b926b06c8acbdae0c24dd2156389196255dbbf4ed662"
		score = 75
		quality = 73
		tags = "FILE"

	strings:
		$boi1 = { 2C ED AC EC 94 7A E8 11 9F DE 00 0C 29 A1 A9 40 }
		$boi2 = { 3F 54 89 18 46 CB E8 11 BD 0E 08 00 27 6D D5 D9 }
		$boi3 = { DE 63 02 FE 57 A2 E8 11 92 E8 5C F3 70 8B 16 F2 }
		$boi4 = { C2 CC 13 98 18 B9 E2 41 82 40 54 A8 AD E2 0A 9A }
		$boi5 = { C4 9D 3A D4 C2 29 3D 47 A9 20 EE A4 D8 A7 D8 7D }
		$boi6 = { E4 51 EC 20 66 61 EA 11 85 CD B2 FC 36 31 EE 21 }
		$boi7 = { 6E DD CE 86 0F 07 90 4B AF 18 38 2F 97 FB 53 62 }
		$boi8 = { 25 41 87 AE F1 D2 EA 11 93 97 00 50 56 C0 00 08 }
		$boi9 = { C4 9D 3A D4 C2 29 3D 47 A9 20 EE A4 D8 A7 D8 7D }
		$boi10 = { 5C 46 EC 05 A6 60 EB 11 85 EB 8C 16 45 31 19 7F }
		$boi11 = { 30 8B 17 86 9B 35 C5 40 A7 9D 48 5C D6 3D F3 5C }
		$boi12 = { E5 21 1D 04 9D A4 E9 11 A9 37 00 0C 29 0F 29 89 }
		$boi13 = { 34 5F AC 8A 4E CE ED 4D 8E 55 83 8E EA 24 B3 4E }
		$boi14 = { 49 77 25 3B D6 E1 EB 11 9C BB 00 D8 61 85 FD 9F }
		$mac1 = { 00 0C 29 A1 A9 40 }
		$mac2 = { 08 00 27 6D D5 D9 }
		$mac3 = { 5C F3 70 8B 16 F2 }
		$mac4 = { 00 0C 29 5A 39 04 }
		$mac5 = { B2 FC 36 31 EE 21 }
		$mac6 = { 00 50 56 C0 00 08 }
		$mac7 = { 8C 16 45 31 19 7F }
		$mac8 = { 00 0C 29 0F 29 89 }
		$mac9 = { 00 D8 61 85 FD 9F }

	condition:
		uint16(0)==0x004c and uint32(4)==0x00021401 and filesize <3KB and (1 of ($boi*) and 1 of ($mac*))
}