
rule RUSSIANPANDA_Jinxloader : FILE
{
	meta:
		description = "Detects JinxLoader Golang version"
		author = "RussianPanda"
		id = "25570c99-5938-5be0-a153-a07be0d0571c"
		date = "2024-01-02"
		modified = "2024-01-02"
		reference = "https://github.com/RussianPanda95/Yara-Rules"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/c65f3c62711bf141e4eb926ffe3a9880e5331974/JinxLoader/JinxLoader-1-2-2024.yar#L1-L16"
		license_url = "N/A"
		hash = "6bd7ff5d764214f239af2bb58b368308c2d04f1147678c2f638f37a893995f71"
		logic_hash = "13dee435fb4d40c629c0a30b6f655b87f14b10a6f6acf61d00e6c692c9bb0ff1"
		score = 75
		quality = 81
		tags = "FILE"

	strings:
		$s1 = {72 75 6E 74 69 6D 65 2E 67 6F 70 61 6E 69 63}
		$s2 = {48 8D 05 4D 6E 07 00 BB 0A 00 00 00}
		$s3 = {73 65 6C 66 5F 64 65 73 74 72 75 63 74 2E 62 61 74}
		$s4 = {48 8D 1D B7 24 08 00 [25] E8 EF FC E4 FF}

	condition:
		uint16(0)==0x5A4D and all of ($s*) and filesize <9MB
}