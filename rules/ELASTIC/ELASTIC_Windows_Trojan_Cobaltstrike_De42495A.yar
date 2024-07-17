
rule ELASTIC_Windows_Trojan_Cobaltstrike_De42495A : FILE MEMORY
{
	meta:
		description = "Identifies Mimikatz module from Cobalt Strike"
		author = "Elastic Security"
		id = "de42495a-0002-466e-98b9-19c9ebb9240e"
		date = "2021-03-23"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_CobaltStrike.yar#L271-L301"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "2a13c73d221d80d25a432f9e0a1387153a78f58719066586e9d80d17613293ef"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "dab3c25809ec3af70df5a8a04a2efd4e8ecb13a4c87001ea699e7a1512973b82"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "\\\\.\\pipe\\mimikatz" ascii fullword
		$b1 = "ERROR kuhl_m_dpapi_chrome ; Input 'Login Data' file needed (/in:\"%%localappdata%%\\Google\\Chrome\\User Data\\Default\\Login Da" wide
		$b2 = "ERROR kuhl_m_lsadump_getUsersAndSamKey ; kull_m_registry_RegOpenKeyEx SAM Accounts (0x%08x)" wide fullword
		$b3 = "ERROR kuhl_m_lsadump_getUsersAndSamKey ; kuhl_m_lsadump_getSamKey KO" wide fullword
		$b4 = "ERROR kuhl_m_lsadump_getComputerAndSyskey ; kull_m_registry_RegOpenKeyEx LSA KO" wide fullword
		$b5 = "ERROR kuhl_m_lsadump_lsa_getHandle ; OpenProcess (0x%08x)" wide fullword
		$b6 = "ERROR kuhl_m_lsadump_enumdomains_users ; SamLookupNamesInDomain: %08x" wide fullword
		$b7 = "mimikatz(powershell) # %s" wide fullword
		$b8 = "powershell_reflective_mimikatz" ascii fullword
		$b9 = "mimikatz_dpapi_cache.ndr" wide fullword
		$b10 = "mimikatz.log" wide fullword
		$b11 = "ERROR mimikatz_doLocal" wide
		$b12 = "mimikatz_x64.compressed" wide

	condition:
		1 of ($a*) and 7 of ($b*)
}