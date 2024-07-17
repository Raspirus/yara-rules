rule SIGNATURE_BASE_Hiddencobra_R4_Wiper_1 : FILE
{
	meta:
		description = "Detects HiddenCobra Wiper"
		author = "NCCIC Partner"
		id = "4978c190-7b66-5cea-96df-809f85620986"
		date = "2017-12-12"
		modified = "2023-12-05"
		reference = "https://www.us-cert.gov/sites/default/files/publications/MAR-10135536.11.WHITE.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_hiddencobra_wiper.yar#L8-L20"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "0e88b7f8491e87cce0deb5f246ca521bdb556b9c79c697559bdf8b0b332e714e"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$mbr_code = { 33 C0 8E D0 BC 00 7C FB 50 07 50 1F FC BE 5D 7C 33 C9 41 81 F9 00 ?? 74 24 B4 43 B0 00 CD 13 FE C2 80 FA 84 7C F3 B2 80 BF 65 7C 81 05 00 04 83 55 02 00 83 55 04 00 83 55 06 00 EB D5 BE 4D 7C B4 43 B0 00 CD 13 33 C9 BE 5D 7C EB C5 }
		$controlServiceFoundlnBoth = { 83 EC 1C 57 68 3F 00 0F 00 6A 00 6A 00 FF 15 ?? ?? ?? ?? 8B F8 85 FF 74 44 8B 44 24 24 53 56 6A 24 50 57 FF 15 ?? ?? ?? ?? 8B 1D ?? ?? ?? ?? 8B F0 85 F6 74 1C 8D 4C 24 0C 51 6A 01 56 FF 15 ?? ?? ?? ?? 68 E8 03 00 00 FF 15 ?? ?? ?? ?? 56 FF D3 57 FF D3 5E 5B 33 C0 5F 83 C4 1C C3 33 C0 5F 83 C4 1C C3 }

	condition:
		uint16(0)==0x5a4d and uint16( uint32(0x3c))==0x4550 and any of them
}