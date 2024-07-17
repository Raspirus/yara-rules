rule ELASTIC_Linux_Hacktool_Cleanlog_3Eb725D1 : FILE MEMORY
{
	meta:
		description = "Detects Linux Hacktool Cleanlog (Linux.Hacktool.Cleanlog)"
		author = "Elastic Security"
		id = "3eb725d1-24de-427a-b6ed-3ca03c0716df"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Hacktool_Cleanlog.yar#L21-L39"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "4df4ebcc61ab2cdb8e5112eeb4e2f29e4e841048de43d7426b1ec11afe175bf6"
		logic_hash = "a9530aca53d935f3e77a5f0fc332db16e3a2832be67c067e5a6d18e7ec00e39f"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "54d3c59ba5ca16fbe99a4629f4fe7464d13f781985a7f35d05604165f9284483"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 45 E0 83 45 C0 01 EB 11 83 45 DC 01 EB 0B 83 45 D8 01 EB 05 83 45 }

	condition:
		all of them
}