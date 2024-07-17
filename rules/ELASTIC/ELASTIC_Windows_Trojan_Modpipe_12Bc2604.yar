rule ELASTIC_Windows_Trojan_Modpipe_12Bc2604 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Modpipe (Windows.Trojan.ModPipe)"
		author = "Elastic Security"
		id = "12bc2604-d3fe-40d6-8a7c-5bd53e403453"
		date = "2023-07-27"
		modified = "2023-09-20"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_ModPipe.yar#L1-L21"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "0a26de1b2fb48d65cde61b60c0eba478da73a3eeaeb785d1b2d6095eccbe34e2"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "30ff9f28cec84496ae7c809ec0401bc10573c690d93f3fb3865b5a913508795e"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/4.0)" fullword
		$a2 = "/robots.txt" fullword
		$a3 = "www.yahoo.com/?"
		$a4 = "www.google.com/?"

	condition:
		all of them
}