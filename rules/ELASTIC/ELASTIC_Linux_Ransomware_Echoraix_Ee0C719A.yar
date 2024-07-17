rule ELASTIC_Linux_Ransomware_Echoraix_Ee0C719A : FILE MEMORY
{
	meta:
		description = "Detects Linux Ransomware Echoraix (Linux.Ransomware.EchoRaix)"
		author = "Elastic Security"
		id = "ee0c719a-1f04-45ff-9e49-38028b138fd0"
		date = "2023-07-29"
		modified = "2024-02-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Ransomware_EchoRaix.yar#L21-L40"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "e711b2d9323582aa390cf34846a2064457ae065c7d2ee1a78f5ed0859b40f9c0"
		logic_hash = "3ca12ea0f1794935ea570dda83f33d04ffb19b6664cc1c8b1cbeed59ac04a01a"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "073d62ce55b1940774ffadeb5b76343aa49bd0a36cf82d50e2bae44f6049a1e8"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a1 = { 24 10 89 44 24 68 8B 4C 24 14 8B 54 24 18 85 C9 74 57 74 03 8B }
		$a2 = { 6D 61 69 6E 2E 43 68 65 63 6B 49 73 52 75 6E 6E 69 6E 67 }

	condition:
		all of them
}