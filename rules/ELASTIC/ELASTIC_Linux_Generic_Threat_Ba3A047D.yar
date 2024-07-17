rule ELASTIC_Linux_Generic_Threat_Ba3A047D : FILE MEMORY
{
	meta:
		description = "Detects Linux Generic Threat (Linux.Generic.Threat)"
		author = "Elastic Security"
		id = "ba3a047d-effc-444b-85b7-d31815e61dfb"
		date = "2024-01-22"
		modified = "2024-02-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Generic_Threat.yar#L369-L388"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "3064e89f3585f7f5b69852f1502e34a8423edf5b7da89b93fb8bd0bef0a28b8b"
		logic_hash = "ffcfb90c0c796b7b343adbd2142193759ececddd0700c0bb4e2898947464b1a2"
		score = 75
		quality = 71
		tags = "FILE, MEMORY"
		fingerprint = "3f43a4e73a857d07c3623cf0278eecf26ef51f4a75b7913a72472ba6738adeac"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a1 = { 52 65 61 64 69 6E 67 20 61 74 20 6D 61 6C 69 63 69 6F 75 73 5F 78 20 3D 20 25 70 2E 2E 2E 20 }
		$a2 = { 28 73 65 63 6F 6E 64 20 62 65 73 74 3A 20 30 78 25 30 32 58 20 73 63 6F 72 65 3D 25 64 29 }

	condition:
		all of them
}