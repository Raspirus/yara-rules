rule ELASTIC_Linux_Trojan_Generic_378765E4 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Generic (Linux.Trojan.Generic)"
		author = "Elastic Security"
		id = "378765e4-c0f2-42ad-a42b-b992d3b866f4"
		date = "2021-04-06"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Generic.yar#L81-L99"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "1ed42910e09e88777ae9958439d14176cb77271edf110053e1a29372fce21ec1"
		logic_hash = "dd10305f553fa94ff83fafa84cff3d544f097b617fca20760eef838902e1f7db"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "60f259ba5ffe607b594c2744b9b30c35beab9683f4cd83c2e31556a387138923"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { E8 ?? FB FF FF 83 7D D4 00 79 0A B8 ?? 22 60 00 }

	condition:
		all of them
}