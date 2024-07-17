rule ELASTIC_Linux_Ransomware_Sfile_9E347B52 : FILE MEMORY
{
	meta:
		description = "Detects Linux Ransomware Sfile (Linux.Ransomware.SFile)"
		author = "Elastic Security"
		id = "9e347b52-233a-4956-9f1f-7600c482e280"
		date = "2023-07-29"
		modified = "2024-02-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Ransomware_SFile.yar#L1-L20"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "49473adedc4ee9b1252f120ad8a69e165dc62eabfa794370408ae055ec65db9d"
		logic_hash = "394571fd5746132d15da97428c3afc149435d91d5432eadf1c838d4a6433c7c1"
		score = 75
		quality = 71
		tags = "FILE, MEMORY"
		fingerprint = "094af0030d51d1e28405fc02a51ccc1bedf9e083b3d24b82c36f4b397eefbb0b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a1 = { 49 74 27 73 20 6A 75 73 74 20 61 20 62 75 73 69 6E 65 73 73 2E }
		$a2 = { 41 6C 6C 20 64 61 74 61 20 69 73 20 70 72 6F 70 65 72 6C 79 20 70 72 6F 74 65 63 74 65 64 20 61 67 61 69 6E 73 74 20 75 6E 61 75 74 68 6F 72 69 7A 65 64 20 61 63 63 65 73 73 20 62 79 20 73 74 65 61 64 79 20 65 6E 63 72 79 70 74 69 6F 6E 20 74 65 63 68 6E 6F 6C 6F 67 79 2E }

	condition:
		all of them
}