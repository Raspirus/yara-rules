
rule ELASTIC_Windows_Trojan_Cobaltstrike_29374056 : FILE MEMORY
{
	meta:
		description = "Identifies Cobalt Strike MZ Reflective Loader."
		author = "Elastic Security"
		id = "29374056-03ce-484b-8b2d-fbf75be86e27"
		date = "2021-03-23"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_CobaltStrike.yar#L766-L785"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "09755b23a7057c70f3ea242ec48549de65ebc6f13bdc38cbe22d6d758c3718cf"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "4cd7552a499687ac0279fb2e25722f979fc5a22afd1ea4abba14a2ef2002dd0f"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 4D 5A 41 52 55 48 89 E5 48 81 EC 20 00 00 00 48 8D 1D ?? FF FF FF 48 81 C3 ?? ?? 00 00 FF D3 }
		$a2 = { 4D 5A E8 00 00 00 00 5B 89 DF 52 45 55 89 E5 }

	condition:
		1 of ($a*)
}