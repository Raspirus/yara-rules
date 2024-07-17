rule ELASTIC_Linux_Shellcode_Generic_30C70926 : FILE MEMORY
{
	meta:
		description = "Detects Linux Shellcode Generic (Linux.Shellcode.Generic)"
		author = "Elastic Security"
		id = "30c70926-9414-499a-a4db-7c3bb902dd82"
		date = "2021-04-06"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Shellcode_Generic.yar#L41-L59"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "a742e23f26726293b1bff3db72864471d6bb4062db1cc6e1c4241f51ec0e21b1"
		logic_hash = "3594994a911e5428198c472a51de189a6be74895170581ec577c49f8dbb9167a"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "4af586211c56e92b1c60fcd09b4def9801086fbe633418459dc07839fe9c735a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { E3 52 53 89 E1 31 C0 B0 0B CD 80 31 C0 40 CD 80 }

	condition:
		all of them
}