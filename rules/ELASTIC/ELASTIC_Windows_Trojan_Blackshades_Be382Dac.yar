rule ELASTIC_Windows_Trojan_Blackshades_Be382Dac : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Blackshades (Windows.Trojan.BlackShades)"
		author = "Elastic Security"
		id = "be382dac-6a6f-43e4-86bb-c62f0db9b43a"
		date = "2022-02-28"
		modified = "2022-04-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_BlackShades.yar#L28-L46"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "e58e352edaa8ae7f95ab840c53fcaf7f14eb640df9223475304788533713c722"
		logic_hash = "a13e37e7930d2d1ed1aa4fdeb282f11bfeb7fe008625589e2bfeab0beea43580"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "e7031c42e51758358db32d8eba95f43be7dd5c4b57e6f9a76f0c3b925eae4e43"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 09 0E 4C 09 10 54 09 0E 4C 09 10 54 09 0E 4C 09 10 54 09 10 54 }

	condition:
		all of them
}