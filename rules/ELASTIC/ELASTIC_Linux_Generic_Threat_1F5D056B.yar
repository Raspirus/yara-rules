rule ELASTIC_Linux_Generic_Threat_1F5D056B : FILE MEMORY
{
	meta:
		description = "Detects Linux Generic Threat (Linux.Generic.Threat)"
		author = "Elastic Security"
		id = "1f5d056b-1e9c-47f6-a63c-752f4cf130a1"
		date = "2024-05-20"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Generic_Threat.yar#L943-L962"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "99d982701b156fe3523b359498c2d03899ea9805d6349416c9702b1067293471"
		logic_hash = "8ad23b593880dc1bebc95c92d0efc3a90e6b1e143c350e30b1a4258502ce7fc7"
		score = 75
		quality = 71
		tags = "FILE, MEMORY"
		fingerprint = "b44a383deaa361db02b342ea52b4f3db9a604bf8b66203fefa5c5d68c361a1d0"
		severity = 50
		arch_context = "x86, arm64"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a1 = { 61 62 63 64 65 66 67 68 69 6A 6B 6C 6D 6E 6F 70 71 72 73 74 75 76 77 30 31 32 33 34 35 36 37 38 }
		$a2 = { 47 45 54 20 2F 63 6F 6E 66 69 67 20 48 54 54 50 2F 31 2E 30 }

	condition:
		all of them
}