
rule ELASTIC_Linux_Generic_Threat_B0B891Fb : FILE MEMORY
{
	meta:
		description = "Detects Linux Generic Threat (Linux.Generic.Threat)"
		author = "Elastic Security"
		id = "b0b891fb-f262-4a06-aa3c-be0baeb53172"
		date = "2024-02-21"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Generic_Threat.yar#L740-L759"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "d666bc0600075f01d8139f8b09c5f4e4da17fa06a86ebb3fa0dc478562e541ae"
		logic_hash = "9ec82691a230f3240b1253f99a45cd0baa3238b6fd533004a22a6152b6ac9a12"
		score = 75
		quality = 71
		tags = "FILE, MEMORY"
		fingerprint = "c6e4f7bcc94b584f8537724d3ecd9f83e6c3981cdc35d5cdc691730ed0e435ef"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a1 = { 6D 61 69 6E 2E 65 6E 63 72 79 70 74 5F 66 69 6C 65 }
		$a2 = { 2F 64 65 76 2F 75 72 61 6E 64 6F 6D 2F 6D 6E 74 2F 65 78 74 2F 6F 70 74 31 35 32 35 38 37 38 39 30 36 32 35 37 36 32 39 33 39 34 35 33 31 32 35 42 69 64 69 5F 43 6F 6E 74 72 6F 6C 4A 6F 69 6E 5F 43 6F 6E 74 72 6F 6C 4D 65 65 74 65 69 5F 4D 61 79 65 6B 50 61 68 61 77 68 5F 48 6D 6F 6E 67 53 6F 72 61 5F 53 6F 6D 70 65 6E 67 53 79 6C 6F 74 69 5F 4E 61 67 72 69 61 62 69 20 6D 69 73 6D 61 74 63 68 62 61 64 20 66 6C 75 73 68 47 65 6E 62 61 64 20 67 20 73 74 61 74 75 73 62 61 64 20 72 65 63 6F 76 65 72 79 63 61 6E 27 74 20 68 61 70 70 65 6E 63 61 73 36 34 20 66 61 69 6C 65 64 63 68 61 6E 20 72 65 63 65 69 76 65 64 75 6D 70 69 6E 67 20 68 65 61 70 65 6E 64 20 74 72 61 63 65 67 63 }

	condition:
		all of them
}