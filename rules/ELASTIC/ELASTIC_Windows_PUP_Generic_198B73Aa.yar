
rule ELASTIC_Windows_PUP_Generic_198B73Aa : FILE MEMORY
{
	meta:
		description = "Detects Windows Pup Generic (Windows.PUP.Generic)"
		author = "Elastic Security"
		id = "198b73aa-d7dd-4f28-bf1c-02672a03d031"
		date = "2023-07-27"
		modified = "2023-09-20"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_PUP_Generic.yar#L1-L20"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "a584c34b9dfc2d78bf8a1e594a2ed519d20088184ce1df09e679b2400aa396d3"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "23c11df4ce2ec2d30b1916b73fc94a84b6a817c1686905fd69fa7a6528798d5f"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "[%i.%i]av=[error]" fullword
		$a2 = "not_defined" fullword
		$a3 = "osver=%d.%d-ServicePack %d" fullword

	condition:
		all of them
}