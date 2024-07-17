
rule ELASTIC_Windows_Ransomware_Cuba_95A98E69 : FILE MEMORY
{
	meta:
		description = "Detects Windows Ransomware Cuba (Windows.Ransomware.Cuba)"
		author = "Elastic Security"
		id = "95a98e69-ce6c-40c6-a05b-2366c663ad6e"
		date = "2021-08-04"
		modified = "2021-10-04"
		reference = "https://www.elastic.co/security-labs/cuba-ransomware-campaign-analysis"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Ransomware_Cuba.yar#L23-L44"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "00f18713f860dc8394fb23a1a2b6280d1eb2f20a487c175433a7b495a1ba408d"
		logic_hash = "d17ef93943e826613be4c21ad1e41d1daa33db9da0fa6106bb8ba6334ebe1d08"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "05cfd7803692149a55d9ced84828422b66e8b301c8c2aae9ca33c6b68e29bcf8"
		severity = 90
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "We also inform that your databases, ftp server and file server were downloaded by us to our servers." ascii fullword
		$a2 = "Good day. All your files are encrypted. For decryption contact us." ascii fullword
		$a3 = ".cuba" wide fullword

	condition:
		all of them
}