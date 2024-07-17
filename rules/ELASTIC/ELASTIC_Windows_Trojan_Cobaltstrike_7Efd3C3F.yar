
rule ELASTIC_Windows_Trojan_Cobaltstrike_7Efd3C3F : FILE MEMORY
{
	meta:
		description = "Identifies Hashdump module from Cobalt Strike"
		author = "Elastic Security"
		id = "7efd3c3f-1104-4b46-9d1e-dc2c62381b8c"
		date = "2021-03-23"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_CobaltStrike.yar#L144-L168"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "45a0aaba6c1be016fc5f4051680ee7e3aa62e8a5d9730b7adab08c14ae37da24"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "9e7c7c9a7436f5ee4c27fd46d6f06e7c88f4e4d1166759573cedc3ed666e1838"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 70
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "hashdump.dll" ascii fullword
		$a2 = "hashdump.x64.dll" ascii fullword
		$a3 = "\\\\.\\pipe\\hashdump" ascii fullword
		$a4 = "ReflectiveLoader"
		$a5 = "Global\\SAM" ascii fullword
		$a6 = "Global\\FREE" ascii fullword
		$a7 = "[-] no results." ascii fullword

	condition:
		4 of ($a*)
}