rule ELASTIC_Linux_Hacktool_Lightning_3Bcac358 : FILE MEMORY
{
	meta:
		description = "Detects Linux Hacktool Lightning (Linux.Hacktool.Lightning)"
		author = "Elastic Security"
		id = "3bcac358-b4b9-43ae-b173-bebe0c9ff899"
		date = "2022-11-08"
		modified = "2024-02-13"
		reference = "https://www.intezer.com/blog/research/lightning-framework-new-linux-threat/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Hacktool_Lightning.yar#L50-L72"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "ad16989a3ebf0b416681f8db31af098e02eabd25452f8d781383547ead395237"
		logic_hash = "f260372b9f2ea32f93ff7a30dc8239766e713a1e177a483444b14538741c24af"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "7108fab0ed64416cf16134475972f99c24aaaf8a4165b83287f9bdbf5050933b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a1 = "[+] %s:%s %d,ntop:%s,strport:%s" ascii fullword
		$a2 = "%s: reading file \"%s\"" ascii fullword
		$a3 = "%s: kill(%d): %s" ascii fullword
		$a4 = "%s exec \"%s\": %s" ascii fullword

	condition:
		all of them
}