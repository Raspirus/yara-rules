
rule ELASTIC_Windows_Trojan_Carberp_D6De82Ae : FILE MEMORY
{
	meta:
		description = "Identifies VNC module from the leaked Carberp source code. This could exist in other malware families."
		author = "Elastic Security"
		id = "d6de82ae-9846-40cb-925d-e0a371e1c44c"
		date = "2021-02-07"
		modified = "2021-08-23"
		reference = "https://github.com/m0n0ph1/malware-1/blob/master/Carberp%20Botnet/source%20-%20absource/pro/all%20source/hvnc_dll/HVNC%20Lib/vnc/xvnc.h#L342"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Carberp.yar#L1-L22"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "f98fadb6feab71930bd5c08e85153898d686cc96c84fe349c00bf6d482de9b53"
		logic_hash = "085020755c77b299b2bfd18b34af6c68450c29de67b8ae32ddf2b26299b923ae"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "7ce34f1000749a938b78508c93371d3339cd49f73eeec36b25da13c9d129b85c"
		threat_name = "Windows.Trojan.Carberp"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = ".NET CLR Networking_Perf_Library_Lock_PID_0" ascii wide fullword
		$a2 = "FakeVNCWnd" ascii wide fullword

	condition:
		all of them
}