
rule ELASTIC_Windows_Ransomware_Magniber_97D7575B : FILE MEMORY
{
	meta:
		description = "Detects Windows Ransomware Magniber (Windows.Ransomware.Magniber)"
		author = "Elastic Security"
		id = "97d7575b-8fc7-4c6b-8371-b62842d90613"
		date = "2021-08-03"
		modified = "2021-10-04"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Ransomware_Magniber.yar#L21-L39"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "a2448b93d7c50801056052fb429d04bcf94a478a0a012191d60e595fed63eec4"
		logic_hash = "9c85f98aaae28e9e90a94d6ce18389467013ea6b569f46f6acaf26a6c7e027fc"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "78253be69d9715892ec725918c3c856040323b83aeab8b84c4aac47355876207"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 00 4C 00 4C 00 20 00 59 00 4F 00 55 00 52 00 20 00 44 00 4F 00 43 00 55 00 4D 00 45 00 4E 00 54 00 53 00 20 00 50 00 48 00 4F 00 54 00 4F 00 53 00 20 00 44 00 41 00 54 00 41 00 42 00 41 00 53 00 45 00 53 00 20 00 41 00 4E 00 44 00 20 00 4F 00 54 00 48 00 45 00 52 00 20 00 49 00 4D 00 50 00 4F 00 52 00 54 00 41 00 4E 00 54 00 20 00 46 00 49 00 4C 00 45 00 53 00 20 00 48 00 41 00 56 00 45 00 20 00 42 00 45 00 45 00 4E 00 20 00 45 00 4E 00 43 00 52 00 59 00 50 00 54 00 45 00 44 00 21 00 0D }

	condition:
		any of them
}