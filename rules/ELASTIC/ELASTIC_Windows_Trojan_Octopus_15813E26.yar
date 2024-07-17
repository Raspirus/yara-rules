
rule ELASTIC_Windows_Trojan_Octopus_15813E26 : FILE MEMORY
{
	meta:
		description = "Identifies Octopus, an Open source pre-operation C2 server based on Python and PowerShell"
		author = "Elastic Security"
		id = "15813e26-77f8-46cf-a6a3-ae081925b85a"
		date = "2021-11-10"
		modified = "2022-01-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Octopus.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "0d30b96ead4ccba75e08f6ba1db73cee61a29b5b0c7ee0fb523cbcd61dce9d87"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "a3294547f7e3cead0cd64eb3d2e7dbd8ccfc4d9eedede240a643c8cd114cbcce"
		threat_name = "Windows.Trojan.Octopus"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = "C:\\Users\\UNKNOWN\\source\\repos\\OctopusUnmanagedExe\\OctopusUnmanagedExe\\obj\\x64\\Release\\SystemConfiguration.pdb" ascii fullword

	condition:
		all of them
}