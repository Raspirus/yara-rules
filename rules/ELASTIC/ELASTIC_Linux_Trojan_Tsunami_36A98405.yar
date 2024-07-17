
rule ELASTIC_Linux_Trojan_Tsunami_36A98405 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Tsunami (Linux.Trojan.Tsunami)"
		author = "Elastic Security"
		id = "36a98405-8b95-49cb-98c5-df4a445d9d39"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Tsunami.yar#L101-L119"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "a57de6cd3468f55b4bfded5f1eed610fdb2cbffbb584660ae000c20663d5b304"
		logic_hash = "a32d324d1865a7796faefbc2f209e6043008a696929fe7837afbbc770e6f4c74"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "c76ca23eece4c2d4ec6656ffb40d6e6ea7777d8a904f4775913fe60ebd606cd6"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 05 88 85 50 FF FF FF 0F B6 85 50 FF FF FF 83 E0 0F 83 C8 40 88 85 50 FF }

	condition:
		all of them
}