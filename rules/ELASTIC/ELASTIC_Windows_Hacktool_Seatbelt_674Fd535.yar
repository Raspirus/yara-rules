
rule ELASTIC_Windows_Hacktool_Seatbelt_674Fd535 : FILE MEMORY
{
	meta:
		description = "Detects Windows Hacktool Seatbelt (Windows.Hacktool.Seatbelt)"
		author = "Elastic Security"
		id = "674fd535-f188-4b20-8b5e-69a111bf08e5"
		date = "2022-10-20"
		modified = "2022-11-24"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Hacktool_Seatbelt.yar#L1-L26"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "a0e467aacd383727d46e766f1c45b424a6d46248118c155c22c538e8773b3ae7"
		logic_hash = "1bff820ec5cc9e56e7be4b290a48628115cc1ace5e41278fa76898bf39ef893e"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "cdbafa7507cb723f20ad0c7a288750a0d95792c8fe5ceb5e48c62fd45f2ffc0b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$guid = "AEC32155-D589-4150-8FE7-2900DF4554C8" ascii wide nocase
		$str0 = "LogonId=\"(\\d+)" ascii wide
		$str1 = "Domain=\"(.*)\",Name=\"(.*)\"" ascii wide
		$str2 = "^\\W*([a-z]:\\\\.+?(\\.exe|\\.dll|\\.sys))\\W*" ascii wide
		$str3 = "KB\\d+" ascii wide
		$str4 = "(^https?://.+)|(^ftp://)" ascii wide
		$str5 = "[0-9A-Fa-f]{8}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{12}" ascii wide
		$str6 = "(http|ftp|https|file)://([\\w_-]+(?:(?:\\.[\\w_-]+)+))([\\w.,@?^=%&:/~+#-]*[\\w@?^=%&/~+#-])?" ascii wide

	condition:
		$guid or all of ($str*)
}