rule ELASTIC_Linux_Trojan_Tsunami_87Bcb848 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Tsunami (Linux.Trojan.Tsunami)"
		author = "Elastic Security"
		id = "87bcb848-cd8b-478c-87de-5df8c457024c"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Tsunami.yar#L301-L319"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "575b0dc887d132aa3983e5712b8f642b03762b0685fbd5a32c104bca72871857"
		logic_hash = "60e8aa7e27ea0bec665075a373ce150c21af4cddfd511b7ec771293126f0006c"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "ffd1a95ba4801bb51ce9b688bdb9787d4a8e3bc3a60ad0f52073f5c531bc6df7"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 65 6D 6F 74 65 00 52 65 6D 6F 74 65 20 49 52 43 20 42 6F 74 00 23 }

	condition:
		all of them
}