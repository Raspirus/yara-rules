rule ELASTIC_Linux_Downloader_Generic_0Bd15Ae0 : FILE MEMORY
{
	meta:
		description = "Detects Linux Downloader Generic (Linux.Downloader.Generic)"
		author = "Elastic Security"
		id = "0bd15ae0-e4fe-48a9-84a6-f8447b467651"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Downloader_Generic.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "e511efb068e76a4a939c2ce2f2f0a089ef55ca56ee5f2ba922828d23e6181f09"
		logic_hash = "c9558562d9e9d3b55bd1fba9e55b332e6b4db5a170e0dd349bef1e35f0c7fd21"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "67e14ea693baee8437157f6e450ac5e469b1bab7d9ff401493220575aae9bc91"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 89 D0 83 C0 01 EB 05 B8 FF FF FF FF 48 8B 5D E8 64 48 33 1C 25 28 00 }

	condition:
		all of them
}