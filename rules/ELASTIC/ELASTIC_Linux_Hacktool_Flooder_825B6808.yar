
rule ELASTIC_Linux_Hacktool_Flooder_825B6808 : FILE MEMORY
{
	meta:
		description = "Detects Linux Hacktool Flooder (Linux.Hacktool.Flooder)"
		author = "Elastic Security"
		id = "825b6808-9b23-4a55-9f26-a34cab6ea92b"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Hacktool_Flooder.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "7db9a0760dd16e23cb299559a0e31a431b836a105d5309a9880fa4b821937659"
		logic_hash = "f5f997d8401f1505e81072dcb0e24ad7a78f0b56133698b70d8dd93ef25ddaf3"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "e2db86e614b9bc0de06daf626abe652cc6385cca8ba96a2f2e394cf82be7a29b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 10 83 EC 04 8B 45 E4 FF 70 0C 8D 45 E8 83 C0 04 50 8B 45 E4 8B }

	condition:
		all of them
}