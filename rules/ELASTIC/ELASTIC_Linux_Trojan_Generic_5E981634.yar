
rule ELASTIC_Linux_Trojan_Generic_5E981634 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Generic (Linux.Trojan.Generic)"
		author = "Elastic Security"
		id = "5e981634-e34e-4943-bf8f-86cfd9fffc85"
		date = "2022-01-05"
		modified = "2022-01-26"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Generic.yar#L221-L239"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "448e8d71e335cabf5c4e9e8d2d31e6b52f620dbf408d8cc9a6232a81c051441b"
		logic_hash = "4623c07a15588788ec8a484642a33f2d18127849302d57520a0dac875564f62c"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "57f1e8fa41f6577f41a73e3460ef0c6c5b0a65567ae0962b080dfc8ab18364f5"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 74 1D 8B 44 24 68 89 84 24 A4 00 00 00 8B 44 24 6C 89 84 24 A8 00 }

	condition:
		all of them
}