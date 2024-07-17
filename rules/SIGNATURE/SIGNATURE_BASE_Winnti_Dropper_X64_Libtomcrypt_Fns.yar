import "pe"


import "pe"


import "pe"


import "pe"


import "pe"


import "pe"


rule SIGNATURE_BASE_Winnti_Dropper_X64_Libtomcrypt_Fns : TAU CN APT
{
	meta:
		description = "Designed to catch winnti 4.0 loader and hack tool x64"
		author = "CarbonBlack Threat Research"
		id = "080d837c-248f-5718-b4a2-290495cd3b38"
		date = "2019-08-26"
		modified = "2023-12-05"
		reference = "https://www.carbonblack.com/2019/09/04/cb-tau-threat-intelligence-notification-winnti-malware-4-0/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_winnti.yar#L280-L327"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "39d23f2a12a3b78182e52847e2fdb2d09386765138c37eb7f75edfc680505531"
		score = 75
		quality = 83
		tags = "TAU, CN, APT"
		rule_version = 1
		yara_version = "3.8.1"
		Confidence = "Prod"
		Priority = "High"
		TLP = "White"
		exemplar_hashes = "5ebf39d614c22e750bb8dbfa3bcb600756dd3b36929755db9b577d2b653cd2d1"
		sample_md5 = "794E127D627B3AF9015396810A35AF1C"

	strings:
		$0x140001820 = { 48 83 EC 28 83 3D ?? ?? ?? ?? 00 }
		$0x140001831 = { 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 F8 FF }
		$0x140001842 = { B8 0B 00 E0 0C 48 83 C4 28 C3 }
		$0x14000184c = { 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 F8 FF }
		$0x140001881 = { B8 0C 00 E0 0C 48 83 C4 28 C3 }
		$0x14000188b = { 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 F8 FF }
		$0x1400018e4 = { B8 0D 00 E0 0C 48 83 C4 28 C3 }
		$0x1400018ee = { 48 8D 0D ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 41 B8 A0 01 00 00 E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 01 00 00 00 }
		$0x140001911 = { 33 C0 48 83 C4 28 C3 }
		$0x140001670 = { 40 55 56 57 41 55 41 56 41 57 B8 38 12 00 00 E8 ?? ?? ?? ?? 48 2B E0 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 84 24 10 12 00 00 48 8B AC 24 90 12 00 00 4C 8B B4 24 A0 12 00 00 45 33 FF 44 39 3D ?? ?? ?? ?? 49 8B F1 41 0F B7 F8 4C 8B EA 44 8B D9 66 44 89 7C 24 40 }
		$0x1400016c8 = { B8 01 00 E0 0C }
		$0x1400016d2 = { 48 89 9C 24 30 12 00 00 4D 85 C9 }
		$0x1400016ec = { 8B 9C 24 98 12 00 00 83 FB 01 }
		$0x1400016fc = { 48 8D 54 24 40 }
		$0x140001701 = { 4C 89 A4 24 28 12 00 00 E8 ?? ?? ?? ?? 44 0F B7 64 24 40 66 44 3B E7 }
		$0x140001727 = { 48 8D 54 24 40 41 8B CB E8 ?? ?? ?? ?? 0F B7 94 24 A8 12 00 00 66 39 54 24 40 }
		$0x140001750 = { 41 8B CB E8 ?? ?? ?? ?? 8B F8 83 F8 FF }
		$0x14000175f = { B8 0F 00 E0 0C }
		$0x140001764 = { 4C 8B A4 24 28 12 00 00 }
		$0x14000176c = { 48 8B 9C 24 30 12 00 00 }
		$0x140001774 = { 48 8B 8C 24 10 12 00 00 48 33 CC E8 ?? ?? ?? ?? 48 81 C4 38 12 00 00 41 5F 41 5E 41 5D 5F 5E 5D C3 }
		$0x140001795 = { 48 8D 4C 24 54 33 D2 41 B8 B4 11 00 00 44 89 7C 24 50 E8 ?? ?? ?? ?? 48 8D 44 24 50 48 89 44 24 30 45 0F B7 CC 4D 8B C5 49 8B D6 8B CF 44 89 7C 24 28 44 89 7C 24 20 E8 ?? ?? ?? ?? 85 C0 }
		$0x1400017d5 = { 4C 8D 4C 24 50 44 8B C3 48 8B D5 48 8B CE E8 ?? ?? ?? ?? 48 8D 4C 24 50 8B D8 E8 ?? ?? ?? ?? 8B C3 }
		$0x1400017fb = { B8 04 00 E0 0C }
		$0x140001805 = { B8 03 00 E0 0C }
		$0x14000180f = { B8 02 00 E0 0C }

	condition:
		all of them
}