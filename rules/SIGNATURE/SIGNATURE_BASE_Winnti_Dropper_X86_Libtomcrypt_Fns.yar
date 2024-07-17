import "pe"


rule SIGNATURE_BASE_Winnti_Dropper_X86_Libtomcrypt_Fns : TAU CN APT
{
	meta:
		description = "Designed to catch winnti 4.0 loader and hack tool x86"
		author = "CarbonBlack Threat Research"
		id = "48e7a3b0-55c7-5db5-855f-1614bd00afb4"
		date = "2019-08-26"
		modified = "2023-12-05"
		reference = "https://www.carbonblack.com/2019/09/04/cb-tau-threat-intelligence-notification-winnti-malware-4-0/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_winnti.yar#L329-L370"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "84bfe001758677ff3a0d60d98e29c33ad1525a0afb27b73df750b2131e298879"
		score = 75
		quality = 85
		tags = "TAU, CN, APT"
		rule_version = 1
		yara_version = "3.8.1"
		confidence = "Prod"
		oriority = "High"
		TLP = "White"
		exemplar_hashes = "0fdcbd59d6ad41dda9ae8bab8fad9d49b1357282027e333f6894c9a92d0333b3"
		sample_md5 = "da3b64ec6468a4ec56f977afb89661b1"

	strings:
		$0x401d20 = { 8B 0D ?? ?? ?? ?? 33 C0 85 C9 }
		$0x401d30 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 04 83 F8 ?? }
		$0x401d46 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 83 F8 ?? }
		$0x401d76 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 1C 83 F8 ?? }
		$0x401dc4 = { 56 57 B9 ?? ?? ?? ?? BE ?? ?? ?? ?? BF ?? ?? ?? ?? 33 C0 F3 A5 5F C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 5E C3 }
		$0x401bd0 = { 55 8B EC B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 53 56 57 85 C0 C7 45 FC ?? ?? ?? ?? }
		$0x401bf4 = { 8B 45 14 85 C0 }
		$0x401bff = { 8B 45 18 85 C0 }
		$0x401c14 = { 8B 7D 08 8D 45 FC 50 57 E8 ?? ?? ?? ?? 8B 75 ?? 83 C4 08 66 }
		$0x401c31 = { 8B 45 0C 85 C0 }
		$0x401c3c = { 8D 4D FC 51 57 E8 ?? ?? ?? ?? 66 8B 55 FC 83 C4 08 66 3B 55 24 }
		$0x401c57 = { 8B 5D 20 85 DB }
		$0x401c62 = { 57 E8 ?? ?? ?? ?? 8B D0 83 C4 04 83 FA ?? }
		$0x401c72 = { B9 ?? ?? ?? ?? 33 C0 8D BD 48 EE FF FF C7 85 44 EE FF FF ?? ?? ?? ?? F3 AB 8B 4D 0C 8D 85 44 EE FF FF 50 6A ?? 81 E6 FF FF 00 00 6A ?? 56 51 53 52 E8 ?? ?? ?? ?? 83 C4 1C 85 C0 }
		$0x401caf = { 8B 45 1C 8B 4D 18 8D 95 44 EE FF FF 52 8B 55 14 50 51 52 E8 ?? ?? ?? ?? 8B F0 8D 85 44 EE FF FF 50 E8 ?? ?? ?? ?? 83 C4 14 8B C6 5F 5E 5B 8B E5 5D C3 }
		$0x401ce1 = { 5F 5E B8 ?? ?? ?? ?? 5B 8B E5 5D C3 }
		$0x401ced = { 5F 5E B8 ?? ?? ?? ?? 5B 8B E5 5D C3 }
		$0x401cf9 = { 5F 5E B8 ?? ?? ?? ?? 5B 8B E5 5D C3 }
		$0x401d05 = { 5F 5E B8 ?? ?? ?? ?? 5B 8B E5 5D C3 }
		$0x401d16 = { 5F 5E 5B 8B E5 5D C3 }

	condition:
		all of them
}