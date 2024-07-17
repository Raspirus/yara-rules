rule TRELLIX_ARC_Crime_Ransomware_Windows_Gpgqwerty : RANSOMWARE
{
	meta:
		description = "Detect GPGQwerty ransomware"
		author = "McAfee Labs"
		id = "dcbaf3bd-7d0c-5449-a751-82caaad3b5c2"
		date = "2018-03-21"
		modified = "2020-08-14"
		reference = "https://securingtomorrow.mcafee.com/mcafee-labs/ransomware-takes-open-source-path-encrypts-gnu-privacy-guard/"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/ransomware/RANSOM_GPGQwerty.yar#L1-L26"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		logic_hash = "8e77895cb8e7f33707c5080780a49cb4bf1d35aa7a8df829fdc7a93319ce3897"
		score = 75
		quality = 70
		tags = "RANSOMWARE"
		rule_version = "v1"
		malware_type = "ransomware"
		malware_family = "Ransom:W32/GPGQwerty"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$a = "gpg.exe –recipient qwerty  -o"
		$b = "%s%s.%d.qwerty"
		$c = "del /Q /F /S %s$recycle.bin"
		$d = "cryz1@protonmail.com"

	condition:
		all of them
}