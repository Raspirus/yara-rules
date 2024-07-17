
rule ELASTIC_Linux_Trojan_Mirai_1C0D246D : FILE MEMORY
{
	meta:
		description = "Based off community provided sample"
		author = "Elastic Security"
		id = "1c0d246d-dc23-48d6-accb-1e1db1eba49b"
		date = "2021-04-13"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L1681-L1700"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "211cfe9d158c8a6840a53f2d1db2bf94ae689946fffb791eed3acceef7f0e3dd"
		logic_hash = "7a101e6d2265e09eb6c8d0f1a2fe54c9aa353dfd8bd156926937f4aec86c3ef1"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "b6b6991e016419b1ddf22822ce76401370471f852866f0da25c7b0f4bec530ee"
		threat_name = "Linux.Trojan.Mirai"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { E7 C0 00 51 78 0F 1B FF 8A 7C 18 27 83 2F 85 2E CB 14 50 2E }

	condition:
		all of them
}