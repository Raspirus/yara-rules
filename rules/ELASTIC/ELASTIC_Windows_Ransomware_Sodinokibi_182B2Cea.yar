
rule ELASTIC_Windows_Ransomware_Sodinokibi_182B2Cea : BETA FILE MEMORY
{
	meta:
		description = "Identifies SODINOKIBI/REvil ransomware"
		author = "Elastic Security"
		id = "182b2cea-5aae-443a-9a2e-b3121a0ac8c7"
		date = "2020-06-18"
		modified = "2021-10-04"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.revil"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Ransomware_Sodinokibi.yar#L36-L62"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "1c23effe5f8b35c5e03ebd5e57664c8937259d464f92dda0a9df344b982e8f8c"
		score = 75
		quality = 75
		tags = "BETA, FILE, MEMORY"
		fingerprint = "b71d862f6d45b388a106bf694e2bf5b4e4d78649c396e89bda46eab4206339fe"
		threat_name = "Windows.Ransomware.Sodinokibi"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "expand 32-byte kexpand 16-byte k" ascii fullword
		$b1 = "ServicesActive" wide fullword
		$b2 = "CreateThread" ascii fullword
		$b3 = "GetExitCodeProcess" ascii fullword
		$b4 = "CloseHandle" ascii fullword
		$b5 = "SetErrorMode" ascii fullword
		$b6 = ":!:(:/:6:C:\\:m:" ascii fullword

	condition:
		($a1 and 6 of ($b*))
}