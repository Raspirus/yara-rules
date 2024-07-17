rule ELASTIC_Windows_Trojan_Trickbot_32930807 : FILE MEMORY
{
	meta:
		description = "Targets cookiesdll.dll module containing functionality used to retrieve browser cookie data"
		author = "Elastic Security"
		id = "32930807-30bb-4c57-8e17-0da99a816405"
		date = "2021-03-30"
		modified = "2021-10-04"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Trickbot.yar#L787-L808"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "e999b83629355ec7ff3b6fda465ef53ce6992c9327344fbf124f7eb37808389d"
		logic_hash = "e98503696bd72cab4d0d1633991bdb87c0537fd1e2d95507ccd474125328f318"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "0aeb68977f4926272f27d5fba44e66bdbb9d6a113da5d7b4133a379b06df4474"
		threat_name = "Windows.Trojan.Trickbot"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "select name, encrypted_value, host_key, path, length(encrypted_value), creation_utc, expires_utc from cookies where datetime(exp"
		$a2 = "Cookies send failure: servers unavailable" ascii fullword
		$a3 = "<moduleconfig>"

	condition:
		all of them
}