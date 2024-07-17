
rule ELASTIC_Linux_Trojan_Xpmmap_7Dcc3534 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Xpmmap (Linux.Trojan.Xpmmap)"
		author = "Elastic Security"
		id = "7dcc3534-e94c-4c92-ac9b-a82b00fb045b"
		date = "2021-04-06"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Xpmmap.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "765546a981921187a4a2bed9904fbc2ccb2a5876e0d45c72e79f04a517c1bda3"
		logic_hash = "f88cc0f02797651e8cdf8e25b67a92f7825ec616b79df21daae798b613baf334"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "397618543390fb8fd8b198f63034fe88b640408d75b769fb337433138dafcf66"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 48 89 45 F8 48 83 7D F8 FF 75 14 BF 10 0C 40 00 }

	condition:
		all of them
}