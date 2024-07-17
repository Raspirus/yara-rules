rule ELASTIC_Windows_Trojan_Oskistealer_A158B1E3 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Oskistealer (Windows.Trojan.OskiStealer)"
		author = "Elastic Security"
		id = "a158b1e3-21b7-4009-9646-6bee9bde98ad"
		date = "2022-03-21"
		modified = "2022-04-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_OskiStealer.yar#L1-L23"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "568cd515c9a3bce7ef21520761b02cbfc95d8884d5b2dc38fc352af92356c694"
		logic_hash = "0ddbe0b234ed60f5a3fc537cdaebf39f639ee24fd66143c9036a9f4786d4c51b"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "3996a89d37494b118654f3713393f415c662850a5a76afa00e83f9611aee3221"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "\"os_crypt\":{\"encrypted_key\":\"" ascii fullword
		$a2 = "%s / %s" ascii fullword
		$a3 = "outlook.txt" ascii fullword
		$a4 = "GLoX6gmCFw==" ascii fullword
		$a5 = "KaoQpEzKSjGm8Q==" ascii fullword

	condition:
		all of them
}