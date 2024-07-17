
rule ELASTIC_Linux_Shellcode_Generic_24B9Aa12 : FILE MEMORY
{
	meta:
		description = "Detects Linux Shellcode Generic (Linux.Shellcode.Generic)"
		author = "Elastic Security"
		id = "24b9aa12-92b2-492d-9a0e-078cdab5830a"
		date = "2021-04-06"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Shellcode_Generic.yar#L101-L119"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "24b2c1ccbbbe135d40597fbd23f7951d93260d0039e0281919de60fa74eb5977"
		logic_hash = "4685253eb00a21d6dd6e874ff68209f20c8668262f24767086687555ccf934aa"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "0ded0ad2fdfff464bf9a0b5a59b8edfe1151a513203386daae6f9f166fd48e5c"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 6E 89 E3 89 C1 89 C2 B0 0B CD 80 31 C0 40 CD 80 }

	condition:
		all of them
}