rule ELASTIC_Linux_Hacktool_Flooder_50158A6E : FILE MEMORY
{
	meta:
		description = "Detects Linux Hacktool Flooder (Linux.Hacktool.Flooder)"
		author = "Elastic Security"
		id = "50158a6e-d412-4e37-a8b5-c7c79a2a5393"
		date = "2021-06-28"
		modified = "2021-09-16"
		reference = "1e0cdb655e48d21a6b02d2e1e62052ffaaec9fdfe65a3d180fc8afabc249e1d8"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Hacktool_Flooder.yar#L580-L598"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "67c22fcf514a3e8c2c27817798c796aacf00ba82e1090894aa2c1170a1e2a096"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "f6286d1fd84aad72cdb8c655814a9df1848fae94ae931ccf62187c100b27a349"
		severity = "100"
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 45 F8 48 01 D0 48 89 45 D8 0F B7 45 E6 48 8D 50 33 48 8B 45 F8 48 }

	condition:
		all of them
}