rule ELASTIC_Linux_Hacktool_Cleanlog_400B7595 : FILE MEMORY
{
	meta:
		description = "Detects Linux Hacktool Cleanlog (Linux.Hacktool.Cleanlog)"
		author = "Elastic Security"
		id = "400b7595-c3c4-4999-b3b9-dcfe9b5df3f6"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Hacktool_Cleanlog.yar#L41-L59"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "4df4ebcc61ab2cdb8e5112eeb4e2f29e4e841048de43d7426b1ec11afe175bf6"
		logic_hash = "e36acf708875efda88143124e11fef5b0e2f99d17b0c49344db969cf0d454db1"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "4423f1597b199046bfc87923e3e229520daa2da68c4c4a3ac69127ace518f19a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 72 20 65 6E 74 72 79 20 28 64 65 66 61 75 6C 74 3A 20 31 73 74 20 }

	condition:
		all of them
}