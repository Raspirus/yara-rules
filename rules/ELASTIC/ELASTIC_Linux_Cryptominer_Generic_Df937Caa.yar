rule ELASTIC_Linux_Cryptominer_Generic_Df937Caa : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Generic (Linux.Cryptominer.Generic)"
		author = "Elastic Security"
		id = "df937caa-ca6c-4a80-a68c-c265dab7c02c"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Generic.yar#L501-L519"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "19b442c9aa229cd724ed9cbaa73f9dfaf0ed61aa3fd1bee7bf8ba964fc23a2b8"
		logic_hash = "d76a6008576687088f28674fb752e1a79ad2046e0208a65c21d0fcd284812ad8"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "963642e141db6c55bd8251ede57b38792278ded736833564ae455cc553ab7d24"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 04 62 20 0A 10 02 0A 14 60 29 00 02 0C 24 14 60 7D 44 01 70 01 }

	condition:
		all of them
}