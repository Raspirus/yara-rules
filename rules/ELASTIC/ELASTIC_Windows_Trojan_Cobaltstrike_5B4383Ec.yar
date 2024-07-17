rule ELASTIC_Windows_Trojan_Cobaltstrike_5B4383Ec : FILE MEMORY
{
	meta:
		description = "Identifies Portscan module from Cobalt Strike"
		author = "Elastic Security"
		id = "5b4383ec-3c93-4e91-850e-d43cc3a86710"
		date = "2021-03-23"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_CobaltStrike.yar#L362-L392"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "033bd831209958674f6309739d65c58d05acb9d17e53cede1cf171c6d6e84efa"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "283d3d2924e92b31f26ec4fc6b79c51bd652fb1377b6985b003f09f8c3dba66c"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "portscan.x64.dll" ascii fullword
		$a2 = "portscan.dll" ascii fullword
		$a3 = "\\\\.\\pipe\\portscan" ascii fullword
		$b1 = "(ICMP) Target '%s' is alive. [read %d bytes]" ascii fullword
		$b2 = "(ARP) Target '%s' is alive. " ascii fullword
		$b3 = "TARGETS!12345" ascii fullword
		$b4 = "ReflectiveLoader" ascii fullword
		$b5 = "%s:%d (platform: %d version: %d.%d name: %S domain: %S)" ascii fullword
		$b6 = "Scanner module is complete" ascii fullword
		$b7 = "pingpong" ascii fullword
		$b8 = "PORTS!12345" ascii fullword
		$b9 = "%s:%d (%s)" ascii fullword
		$b10 = "PREFERENCES!12345" ascii fullword

	condition:
		2 of ($a*) or 6 of ($b*)
}