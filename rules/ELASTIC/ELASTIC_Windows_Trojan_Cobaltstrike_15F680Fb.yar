rule ELASTIC_Windows_Trojan_Cobaltstrike_15F680Fb : FILE MEMORY
{
	meta:
		description = "Identifies Netview module from Cobalt Strike"
		author = "Elastic Security"
		id = "15f680fb-a04f-472d-a182-0b9bee111351"
		date = "2021-03-23"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_CobaltStrike.yar#L330-L360"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "0efe368ad82f5b0f6301121bfda9fd049b008ac246368bfa22bd976fa2c56b79"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "0ecb8e41c01bf97d6dea4cf6456b769c6dd2a037b37d754f38580bcf561e1d2c"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "netview.x64.dll" ascii fullword
		$a2 = "netview.dll" ascii fullword
		$a3 = "\\\\.\\pipe\\netview" ascii fullword
		$b1 = "Sessions for \\\\%s:" ascii fullword
		$b2 = "Account information for %s on \\\\%s:" ascii fullword
		$b3 = "Users for \\\\%s:" ascii fullword
		$b4 = "Shares at \\\\%s:" ascii fullword
		$b5 = "ReflectiveLoader" ascii fullword
		$b6 = "Password changeable" ascii fullword
		$b7 = "User's Comment" wide fullword
		$b8 = "List of hosts for domain '%s':" ascii fullword
		$b9 = "Password changeable" ascii fullword
		$b10 = "Logged on users at \\\\%s:" ascii fullword

	condition:
		2 of ($a*) or 6 of ($b*)
}