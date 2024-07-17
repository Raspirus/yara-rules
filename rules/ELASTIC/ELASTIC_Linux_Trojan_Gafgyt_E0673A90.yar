
rule ELASTIC_Linux_Trojan_Gafgyt_E0673A90 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "e0673a90-165e-4347-a965-e8d14fdf684b"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L316-L334"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "c5a317d0d8470814ff343ce78ad2428ebb3f036763fcf703a589b6c4d33a3ec6"
		logic_hash = "149147eedd66f9ca2dad9cb69f37abc849d44331ec1b5d2917ab3867ced0b274"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "6834f65d54bbfb926f986fe2dd72cd30bf9804ed65fcc71c2c848e72350f386a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 45 E8 0F B6 00 84 C0 74 17 48 8B 75 E8 48 FF C6 48 8B 7D F0 48 }

	condition:
		all of them
}