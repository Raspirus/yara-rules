
rule ELASTIC_Windows_Trojan_Sourshark_F0247Cce : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Sourshark (Windows.Trojan.SourShark)"
		author = "Elastic Security"
		id = "f0247cce-b983-41a1-9118-fd4c23e3d099"
		date = "2024-06-04"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_SourShark.yar#L1-L21"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "07eb88c69437ee6e3ea2fbab5f2fbd8e846125d18c1da7d72bb462e9d083c9fc"
		logic_hash = "0c5d802b5bfc771bdf5df541b18c7ab9de4f420fd3928bfd85b1a71cca2af1bc"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "174d6683890b855a06c672423b4a0b3aa291558d8a2af4771b931d186ce3cb63"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "%s\\svchost.%s"
		$a2 = "crypto_domain"
		$a3 = "postback_id"

	condition:
		all of them
}