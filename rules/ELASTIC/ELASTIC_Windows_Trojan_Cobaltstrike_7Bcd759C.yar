
rule ELASTIC_Windows_Trojan_Cobaltstrike_7Bcd759C : FILE MEMORY
{
	meta:
		description = "Identifies SSH Agent module from Cobalt Strike"
		author = "Elastic Security"
		id = "7bcd759c-8e3d-4559-9381-1f4fe8b3dd95"
		date = "2021-03-23"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_CobaltStrike.yar#L627-L648"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "bfbb8e8009182e87c49242ec3da6e98b23447b646f5c7ea5f97196ae929d7c5f"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "553085f1d1ca8dcd797360b287951845753eee7370610a1223c815a200a5ed20"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "sshagent.x64.dll" ascii fullword
		$a2 = "sshagent.dll" ascii fullword
		$b1 = "\\\\.\\pipe\\sshagent" ascii fullword
		$b2 = "\\\\.\\pipe\\PIPEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii fullword

	condition:
		1 of ($a*) and 1 of ($b*)
}