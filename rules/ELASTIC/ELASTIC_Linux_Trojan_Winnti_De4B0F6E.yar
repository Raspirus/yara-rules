rule ELASTIC_Linux_Trojan_Winnti_De4B0F6E : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Winnti (Linux.Trojan.Winnti)"
		author = "Elastic Security"
		id = "de4b0f6e-0183-4ea8-9c03-f716a25f1884"
		date = "2022-01-05"
		modified = "2022-01-26"
		reference = "a6b9b3ea19eaddd4d90e58c372c10bbe37dbfced638d167182be2c940e615710"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Winnti.yar#L61-L79"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "fb7b0ff4757dfc1ba2ca8585d5ddf14aae03063e10bdc2565443362c6ba37c30"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "c72eddc2d72ea979ad4f680d060aac129f1cd61dbdf3b0b5a74f5d35a9fe69d7"
		severity = "100"
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 85 30 FF FF FF 02 00 48 8D 85 30 FF FF FF 48 8D 50 02 0F B7 85 28 FF }

	condition:
		all of them
}