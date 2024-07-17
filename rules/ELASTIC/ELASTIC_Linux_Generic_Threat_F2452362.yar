
rule ELASTIC_Linux_Generic_Threat_F2452362 : FILE MEMORY
{
	meta:
		description = "Detects Linux Generic Threat (Linux.Generic.Threat)"
		author = "Elastic Security"
		id = "f2452362-dc55-452f-9e93-e6a6b74d8ebd"
		date = "2024-05-21"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Generic_Threat.yar#L1046-L1065"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "5ff46c27b5823e55f25c9567d687529a24a0d52dea5bc2423b36345782e6b8f6"
		logic_hash = "95d51077cb7c0f4b089a2e2ee8fcbab204264ade7ddd64fc1ee0176183dc84e0"
		score = 75
		quality = 71
		tags = "FILE, MEMORY"
		fingerprint = "cc293c87513ca1332e5ec13c9ce47efbe5e9c48c0cece435ac3c8bdbc822ea82"
		severity = 50
		arch_context = "x86, arm64"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a1 = { 6F 72 69 67 69 6E 61 6C 5F 72 65 61 64 64 69 72 }
		$a2 = { 45 72 72 6F 72 20 69 6E 20 64 6C 73 79 6D 3A 20 25 73 }

	condition:
		all of them
}