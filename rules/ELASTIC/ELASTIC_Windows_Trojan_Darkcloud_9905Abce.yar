rule ELASTIC_Windows_Trojan_Darkcloud_9905Abce : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Darkcloud (Windows.Trojan.DarkCloud)"
		author = "Elastic Security"
		id = "9905abce-cbfc-4c92-aef6-38f2099eb5da"
		date = "2023-05-03"
		modified = "2023-06-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_DarkCloud.yar#L1-L20"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "500cb8459c19acd5a1144c4b509c14dbddec74ad623896bfe946fde1cd99a571"
		logic_hash = "27d3841d6acf87f5c9c03d643c7859d9eaf42e49ed0241b761f858c669c4e931"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "5aeb210b37f4b2b4032917f53f2fb0422132aa1f8cddf0f47bccf50ff68ce00c"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 8D 45 DC 57 57 6A 01 6A 11 50 6A 01 68 80 00 00 00 89 7D E8 89 }
		$a2 = { C8 33 FF 50 57 FF D6 8D 4D DC 51 57 FF D6 C3 8B 4D F0 8B 45 }

	condition:
		all of them
}