rule ELASTIC_Windows_Ransomware_Ransomexx_Fabff49C : FILE MEMORY
{
	meta:
		description = "Detects Windows Ransomware Ransomexx (Windows.Ransomware.Ransomexx)"
		author = "Elastic Security"
		id = "fabff49c-8e1a-4020-b081-2f432532e529"
		date = "2021-08-07"
		modified = "2021-10-04"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Ransomware_Ransomexx.yar#L1-L22"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "480af18104198ad3db1518501ee58f9c4aecd19dbbf2c5dd7694d1d87e9aeac7"
		logic_hash = "67d5123b706685ea5ab939aec31cb1549297778d91dd38b14e109945c52da71a"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "a7a1e6d5fafdddc7d4699710edf407653968ffd40747c50f26ef63a6cb623bbe"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "ransom.exx" ascii fullword
		$a2 = "Infrastructure rebuild will cost you MUCH more." wide fullword
		$a3 = "Your files are securely ENCRYPTED." wide fullword
		$a4 = "delete catalog -quiet" wide fullword

	condition:
		all of them
}