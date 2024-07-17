rule ELASTIC_Macos_Virus_Maxofferdeal_53Df500F : FILE MEMORY
{
	meta:
		description = "Detects Macos Virus Maxofferdeal (MacOS.Virus.Maxofferdeal)"
		author = "Elastic Security"
		id = "53df500f-3add-4d3d-aec3-35b7b5aa5b35"
		date = "2021-10-05"
		modified = "2021-10-25"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/MacOS_Virus_Maxofferdeal.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "ecd62ef880da057726ca55c6826ce4e1584ec6fc3afaabed7f66154fc39ffef8"
		logic_hash = "ed63c14e31c200f906b525c7ef1cd671511a89c8833cfa1a605fc9870fe91043"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "2f41de7b8e55ef8db39bf84c0f01f8d34d67b087769b84381f2ccc3778e13b08"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"

	strings:
		$a = { BF BF BF E6 AF A7 A7 AF A4 AD E6 AB A7 A5 C8 AC AD AE A9 BD A4 BC 97 }

	condition:
		all of them
}