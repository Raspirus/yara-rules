
rule ELASTIC_Linux_Hacktool_Flooder_F454Ec10 : FILE MEMORY
{
	meta:
		description = "Detects Linux Hacktool Flooder (Linux.Hacktool.Flooder)"
		author = "Elastic Security"
		id = "f454ec10-7a67-4717-9e95-fecb7c357566"
		date = "2022-01-05"
		modified = "2022-01-26"
		reference = "0297e1ad6e180af85256a175183102776212d324a2ce0c4f32e8a44a2e2e9dad"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Hacktool_Flooder.yar#L600-L618"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "e5afb215632ad6359ba95df86316d496ea5e36edb79901c34e0710a6bd9c97d1"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "2ae5e2c3190a4ce5d238efdb10ac0520987425fb7af52246b6bf948abd0259da"
		severity = "100"
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 8B 45 EC 48 63 D0 48 8B 45 D0 48 01 D0 0F B6 00 3C 2E 75 4D 8B }

	condition:
		all of them
}