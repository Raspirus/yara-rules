
rule ELASTIC_Linux_Ransomware_Hellokitty_35731270 : FILE MEMORY
{
	meta:
		description = "Detects Linux Ransomware Hellokitty (Linux.Ransomware.Hellokitty)"
		author = "Elastic Security"
		id = "35731270-b283-4dff-8316-6a541ff1d4d5"
		date = "2023-07-27"
		modified = "2024-02-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Ransomware_Hellokitty.yar#L1-L21"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "556e5cb5e4e77678110961c8d9260a726a363e00bf8d278e5302cb4bfccc3eed"
		logic_hash = "40cb632d6b8561de56f2010a082a24b0c50d4cabed21e073168b5302ddff7044"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "1945bfcbe084f8f6671c73e74679fb2933d2ebea54479fdf348d4804a614279a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a1 = "File Locked:%s PID:%d" fullword
		$a2 = "error encrypt: %s rename back:%s" fullword
		$a3 = "esxcli vm process kill -t=soft -w=%d" fullword

	condition:
		2 of them
}