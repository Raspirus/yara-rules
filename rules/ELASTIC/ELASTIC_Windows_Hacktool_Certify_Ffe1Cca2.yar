
rule ELASTIC_Windows_Hacktool_Certify_Ffe1Cca2 : FILE MEMORY
{
	meta:
		description = "Detects Windows Hacktool Certify (Windows.Hacktool.Certify)"
		author = "Elastic Security"
		id = "ffe1cca2-106c-4197-9d26-eb90331435d9"
		date = "2024-03-27"
		modified = "2024-05-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Hacktool_Certify.yar#L1-L27"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "3c7f759a6c38d0c0780fba2d43be6dcf9e4869d54b66f16c0703ec8e58124953"
		logic_hash = "e1d37ad683bfbe34433dc5e13ae2cf7c873fed640e1c58a3b0274b4b34900e53"
		score = 75
		quality = 71
		tags = "FILE, MEMORY"
		fingerprint = "69f5648f1a9621fe33e63c150d184cb89ceef472885a928aa501a08d8069234d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "<DisplayNtAuthCertificates>b_"
		$a2 = "<PrintAllowPermissions>b_"
		$a3 = "<ShowVulnerableTemplates>b_"
		$a4 = "<ParseCertificateApplicationPolicies>b_"
		$a5 = "<PrintCertTemplate>b_"
		$b1 = "64524ca5-e4d0-41b3-acc3-3bdbefd40c97" ascii wide nocase
		$b2 = "64524CA5-E4D0-41B3-ACC3-3BDBEFD40C97" ascii wide nocase
		$b3 = "Certify.exe find /vulnerable" wide
		$b4 = "Certify.exe request /ca" wide

	condition:
		all of ($a*) or any of ($b*)
}