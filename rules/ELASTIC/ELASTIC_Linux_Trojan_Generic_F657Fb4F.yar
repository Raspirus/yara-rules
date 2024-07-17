
rule ELASTIC_Linux_Trojan_Generic_F657Fb4F : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Generic (Linux.Trojan.Generic)"
		author = "Elastic Security"
		id = "f657fb4f-a065-4d51-bead-fd28f8053418"
		date = "2021-04-06"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Generic.yar#L101-L119"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "1ed42910e09e88777ae9958439d14176cb77271edf110053e1a29372fce21ec1"
		logic_hash = "af4fa2c21b47f360b425ebbfea624e3728cd682e54e367d265b4f3a6515b0720"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "8c15d5e53b95002f569d63c91db7858c4ca8f26c441cb348a1b34f3b26d02468"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { E8 ?? FB FF FF 83 7D D4 00 79 0A B8 ?? ?? 60 00 }

	condition:
		all of them
}