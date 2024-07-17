rule ELASTIC_Windows_Ransomware_Clop_6A1670Aa : BETA FILE MEMORY
{
	meta:
		description = "Identifies CLOP ransomware in unpacked state"
		author = "Elastic Security"
		id = "6a1670aa-7f78-455b-9e28-f39ed4c6476e"
		date = "2020-05-03"
		modified = "2021-08-23"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.clop"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Ransomware_Clop.yar#L1-L20"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "afe28000d50495bf2f2adc6cbf0159591ce87bff207f3c6a1d38e09f9ed328d7"
		score = 75
		quality = 75
		tags = "BETA, FILE, MEMORY"
		fingerprint = "7c24cc6a519922635a519dad412d1a07728317b91f90a120ccc1c7e7e2c8a002"
		threat_name = "Windows.Ransomware.Clop"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$b1 = { FF 15 04 E1 40 00 83 F8 03 74 0A 83 F8 02 }

	condition:
		1 of ($b*)
}