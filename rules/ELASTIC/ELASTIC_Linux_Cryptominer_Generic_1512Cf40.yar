rule ELASTIC_Linux_Cryptominer_Generic_1512Cf40 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Generic (Linux.Cryptominer.Generic)"
		author = "Elastic Security"
		id = "1512cf40-ae62-40cf-935d-589be4fe3d93"
		date = "2021-04-06"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Generic.yar#L281-L299"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "fc063a0e763894e86cdfcd2b1c73d588ae6ecb411c97df2a7a802cd85ee3f46d"
		logic_hash = "0d43e6a4bd5036c2b6adb61f2d7b11e625c20e9a3d29242c7c34cfc7708561be"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "f9800996d2e6d9ea8641d51aedc554aa732ebff871f0f607bb3fe664914efd5a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { C4 10 5B C3 E8 35 A7 F6 FF 0F 1F 44 00 00 53 48 }

	condition:
		all of them
}