rule ELASTIC_Windows_Trojan_Metasploit_Dd5Ce989 : FILE MEMORY
{
	meta:
		description = "Identifies Meterpreter DLL used by Metasploit"
		author = "Elastic Security"
		id = "dd5ce989-3925-4e27-97c1-3b8927c557e9"
		date = "2021-04-14"
		modified = "2021-08-23"
		reference = "https://www.rapid7.com/blog/post/2015/03/25/stageless-meterpreter-payloads/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Metasploit.yar#L142-L164"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "86cf98bf854b01a55e3f306597437900e11d429ac6b7781e090eeda3a5acb360"
		logic_hash = "5c094979be1cd347ffee944816b819b6fbb62804b183a6120cd3a93d2759155b"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "4fc7c309dca197f4626d6dba8afcd576e520dbe2a2dd6f7d38d7ba33ee371d55"
		threat_name = "Windows.Trojan.Metasploit"
		severity = 90
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "metsrv.x64.dll" fullword
		$a2 = "metsrv.dll" fullword
		$b1 = "ReflectiveLoader"

	condition:
		1 of ($a*) and 1 of ($b*)
}