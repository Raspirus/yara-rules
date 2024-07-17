rule ELASTIC_Linux_Shellcode_Generic_224Bdcc4 : FILE MEMORY
{
	meta:
		description = "Detects Linux Shellcode Generic (Linux.Shellcode.Generic)"
		author = "Elastic Security"
		id = "224bdcc4-4b38-44b5-96c6-d3b378628fa4"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Shellcode_Generic.yar#L61-L79"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "bd22648babbee04555cef52bfe3e0285d33852e85d254b8ebc847e4e841b447e"
		logic_hash = "8c4a2bb63f0926e7373caf0a027179b4730cc589f9af66d2071e88f4165b0f73"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "e23b239775c321d4326eff2a7edf0787116dd6d8a9e279657e4b2b01b33e72aa"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 89 E6 6A 10 5A 6A 2A 58 0F 05 48 85 C0 79 1B 49 FF C9 74 22 }

	condition:
		all of them
}