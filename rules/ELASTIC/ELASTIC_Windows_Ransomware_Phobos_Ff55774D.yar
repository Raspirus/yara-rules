rule ELASTIC_Windows_Ransomware_Phobos_Ff55774D : BETA FILE MEMORY
{
	meta:
		description = "Identifies Phobos ransomware"
		author = "Elastic Security"
		id = "ff55774d-4425-4243-8156-ce029c1d5860"
		date = "2020-06-25"
		modified = "2021-08-23"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.phobos"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Ransomware_Phobos.yar#L24-L43"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "9ee41b9638a8cc1d9f9b254878c935c531b2f599be59550b3617b1de8cba2ba5"
		score = 75
		quality = 75
		tags = "BETA, FILE, MEMORY"
		fingerprint = "d8016c9be4a8e5b5ac32b7108542fee8426d65b4d37e2a9c5ad57284abb3781e"
		threat_name = "Windows.Ransomware.Phobos"
		severity = 90
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$c1 = { 24 18 83 C4 0C 8B 4F 0C 03 C6 50 8D 54 24 18 52 51 6A 00 6A 00 89 44 }

	condition:
		1 of ($c*)
}