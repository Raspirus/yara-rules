rule ELASTIC_Macos_Trojan_Metasploit_6Cab0Ec0 : FILE MEMORY
{
	meta:
		description = "Detects Macos Trojan Metasploit (MacOS.Trojan.Metasploit)"
		author = "Elastic Security"
		id = "6cab0ec0-0ac5-4f43-8a10-1f46822a152b"
		date = "2021-09-30"
		modified = "2021-10-25"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/MacOS_Trojan_Metasploit.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "7ab5490dca314b442181f9a603252ad7985b719c8aa35ddb4c3aa4b26dcc8a42"
		logic_hash = "c19fe812b74b034bfb42c0e2ee552d879ed038e054c5870b85e7e610d3184198"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "e13c605d8f16b2b2e65c717a4716c25b3adaec069926385aff88b37e3db6e767"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"

	strings:
		$a = "mettlesploit! " ascii fullword

	condition:
		all of them
}