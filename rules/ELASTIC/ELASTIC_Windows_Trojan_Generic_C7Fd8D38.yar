rule ELASTIC_Windows_Trojan_Generic_C7Fd8D38 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Generic (Windows.Trojan.Generic)"
		author = "Elastic Security"
		id = "c7fd8d38-eaba-424d-b91a-098c439dab6b"
		date = "2022-02-17"
		modified = "2022-04-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Generic.yar#L67-L89"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "a1702ec12c2bf4a52e11fbdab6156358084ad2c662c8b3691918ef7eabacde96"
		logic_hash = "81c56cd741692a7f2a894c2b8f2676aad47f14221228b9466a2ab0f05d76c623"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "dc14cd519b3bbad7c2e655180a584db0a4e2ad4eea073a52c94b0a88152b37ba"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "PCREDENTIAL" ascii fullword
		$a2 = "gHotkey" ascii fullword
		$a3 = "EFORMATEX" ascii fullword
		$a4 = "ZLibEx" ascii fullword
		$a5 = "9Root!" ascii fullword

	condition:
		all of them
}