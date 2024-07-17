rule ELASTIC_Linux_Cryptominer_Generic_A5267Ea3 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Generic (Linux.Cryptominer.Generic)"
		author = "Elastic Security"
		id = "a5267ea3-b98c-49e9-8051-e33a101f12d3"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Generic.yar#L541-L559"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "b342ceeef58b3eeb7a312038622bcce4d76fc112b9925379566b24f45390be7d"
		logic_hash = "081633b5aa0490dbffcc0b8ab9850b59dbbd67d947c0fe68d28338a352e94676"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "8391a4dbc361eec2877852acdc77681b3a15922d9a047d7ad12d06271d53f540"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { EE 6A 00 41 B9 01 00 00 00 48 8D 4A 13 4C 89 E7 88 85 40 FF }

	condition:
		all of them
}