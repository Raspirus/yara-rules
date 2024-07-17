
rule ELASTIC_Windows_Hacktool_Sharphound_5Adf9D6D : FILE MEMORY
{
	meta:
		description = "Detects Windows Hacktool Sharphound (Windows.Hacktool.SharpHound)"
		author = "Elastic Security"
		id = "5adf9d6d-b6db-43ea-95bd-e9747b82a36d"
		date = "2022-10-20"
		modified = "2022-11-24"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Hacktool_SharpHound.yar#L1-L23"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "1f74ed6e61880d19e53cde5b0d67a0507bfda0be661860300dcb0f20ea9a45f4"
		logic_hash = "2c9f38187866985109a42ffdf8940b5d195aadd3815b2de952b190d4b0b95c3c"
		score = 75
		quality = 71
		tags = "FILE, MEMORY"
		fingerprint = "53d295223e2330a973f9495a7ca625c1e9429bc5daf7dda1b84b2aaeca5ea898"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$guid0 = "A517A8DE-5834-411D-ABDA-2D0E1766539C" ascii wide nocase
		$guid1 = "90A6822C-4336-433D-923F-F54CE66BA98F" ascii wide nocase
		$print_str0 = "Initializing SharpHound at {time} on {date}" ascii wide
		$print_str1 = "SharpHound completed {Number} loops! Zip file written to {Filename}" ascii wide
		$print_str2 = "[-] Removed DCOM Collection" ascii wide

	condition:
		$guid0 or $guid1 or all of ($print_str*)
}