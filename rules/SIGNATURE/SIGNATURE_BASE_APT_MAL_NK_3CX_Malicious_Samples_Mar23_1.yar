import "pe"


rule SIGNATURE_BASE_APT_MAL_NK_3CX_Malicious_Samples_Mar23_1 : FILE
{
	meta:
		description = "Detects malicious DLLs related to 3CX compromise"
		author = "X__Junior, Florian Roth (Nextron Systems)"
		id = "a6ea3299-fde5-5206-b5db-eb3a3f5944d9"
		date = "2023-03-29"
		modified = "2023-04-20"
		reference = "https://www.reddit.com/r/crowdstrike/comments/125r3uu/20230329_situational_awareness_crowdstrike/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_mal_3cx_compromise_mar23.yar#L3-L30"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "68f4007791d365900c84e32e076aa3cac9f3a9ed46de297f1005306554ee13f5"
		score = 85
		quality = 85
		tags = "FILE"
		hash1 = "7986bbaee8940da11ce089383521ab420c443ab7b15ed42aed91fd31ce833896"
		hash2 = "c485674ee63ec8d4e8fde9800788175a8b02d3f9416d0e763360fff7f8eb4e02"
		hash3 = "cc4eedb7b1f77f02b962f4b05278fa7f8082708b5a12cacf928118520762b5e2"

	strings:
		$opa1 = { 4C 89 F1 4C 89 EA 41 B8 40 00 00 00 FF 15 ?? ?? ?? ?? 85 C0 74 ?? 4C 89 F0 FF 15 ?? ?? ?? ?? 4C 8D 4C 24 ?? 45 8B 01 4C 89 F1 4C 89 EA FF 15 }
		$opa2 = { 48 C7 44 24 ?? 00 00 00 00 4C 8D 7C 24 ?? 48 89 F9 48 89 C2 41 89 E8 4D 89 F9 FF 15 ?? ?? ?? ?? 41 83 3F 00 0F 84 ?? ?? ?? ?? 0F B7 03 3D 4D 5A 00 00}
		$opa3 = { 41 80 7C 00 ?? FE 75 ?? 41 80 7C 00 ?? ED 75 ?? 41 80 7C 00 ?? FA 75 ?? 41 80 3C 00 CE}
		$opa4 = { 44 0F B6 CD 46 8A 8C 0C ?? ?? ?? ?? 45 30 0C 0E 48 FF C1}
		$opb1 = { 41 B8 40 00 00 00 49 8B D5 49 8B CC FF 15 ?? ?? ?? ?? 85 C0 74 ?? 41 FF D4 44 8B 45 ?? 4C 8D 4D ?? 49 8B D5 49 8B CC FF 15 }
		$opb2 = { 44 8B C3 48 89 44 24 ?? 48 8B 5C 24 ?? 4C 8D 4D ?? 48 8B CB 48 89 74 24 ?? 48 8B D0 4C 8B F8 FF 15 }
		$opb3 = { 80 78 ?? FE 75 ?? 80 78 ?? ED 75 ?? 80 38 FA 75 ?? 80 78 ?? CE }
		$opb4 = { 49 63 C1 44 0F B6 44 05 ?? 44 88 5C 05 ?? 44 88 02 0F B6 54 05 ?? 49 03 D0 0F B6 C2 0F B6 54 05 ?? 41 30 12}

	condition:
		uint16(0)==0x5a4d and filesize <5MB and pe.characteristics&pe.DLL and (2 of ($opa*) or 2 of ($opb*))
}