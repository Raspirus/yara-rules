rule ELASTIC_Windows_Trojan_Emotet_D6Ac1Ea4 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Emotet (Windows.Trojan.Emotet)"
		author = "Elastic Security"
		id = "d6ac1ea4-b0a8-4023-b712-9f4f2c7146a3"
		date = "2022-05-24"
		modified = "2022-06-09"
		reference = "https://www.elastic.co/security-labs/emotet-dynamic-configuration-extraction"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Emotet.yar#L92-L114"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "2c6709d5d2e891d1ce26fdb4021599ac10fea93c7773f5c00bea8e5e90404b71"
		logic_hash = "9b37940ea8752c6db52d4f09225de0389438c41468a11a7cda8f28b191192ef9"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "7e6224c58c283765b5e819eb46814c556ae6b7b5931cd1e3e19ca3ec8fa31aa2"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$calc1 = { C7 44 24 ?? ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? }
		$pre = { 48 83 EC ( 18 | 28 ) C7 44 24 ?? ?? ?? ?? ?? }
		$setup = { 48 8D 05 ?? ?? ?? ?? 48 89 81 ?? ?? ?? ?? }
		$post = { 8B 44 24 ?? 89 44 24 ?? 48 83 C4 18 C3 }

	condition:
		#calc1>=10 and #pre>=5 and #setup>=5 and #post>=5
}