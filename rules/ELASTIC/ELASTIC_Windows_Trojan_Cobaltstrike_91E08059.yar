rule ELASTIC_Windows_Trojan_Cobaltstrike_91E08059 : FILE MEMORY
{
	meta:
		description = "Identifies Post Ex module from Cobalt Strike"
		author = "Elastic Security"
		id = "91e08059-46a8-47d0-91c9-e86874951a4a"
		date = "2021-03-23"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_CobaltStrike.yar#L394-L421"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "d5a8c1a0baa5e915cff29bcac33e30a7d7260f938ecaa6171d3aa88425a69266"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "d8baacb58a3db00489827275ad6a2d007c018eaecbce469356b068d8a758634b"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "postex.x64.dll" ascii fullword
		$a2 = "postex.dll" ascii fullword
		$a3 = "RunAsAdminCMSTP" ascii fullword
		$a4 = "KerberosTicketPurge" ascii fullword
		$b1 = "GetSystem" ascii fullword
		$b2 = "HelloWorld" ascii fullword
		$b3 = "KerberosTicketUse" ascii fullword
		$b4 = "SpawnAsAdmin" ascii fullword
		$b5 = "RunAsAdmin" ascii fullword
		$b6 = "NetDomain" ascii fullword

	condition:
		2 of ($a*) or 4 of ($b*)
}