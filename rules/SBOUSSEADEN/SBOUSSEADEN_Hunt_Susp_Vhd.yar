
rule SBOUSSEADEN_Hunt_Susp_Vhd : FILE
{
	meta:
		description = "Virtual hard disk file with embedded PE"
		author = "SBousseaden"
		id = "14b082b2-c5cd-5f34-85e9-5987650eaacd"
		date = "2020-07-13"
		modified = "2020-07-13"
		reference = "https://github.com/sbousseaden/YaraHunts/"
		source_url = "https://github.com/sbousseaden/YaraHunts//blob/71b27a2a7c57c2aa1877a11d8933167794e2b4fb/hunt_susp_vhd.yara#L1-L12"
		license_url = "N/A"
		logic_hash = "4ba2e3f533942b27c1d235be4677afdac774b558429c414043a8e3a609123ad3"
		score = 65
		quality = 73
		tags = "FILE"

	strings:
		$hvhd = {636F6E6563746978}
		$s1 = {4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00}
		$s2 = "!This program cannot be run in DOS mode." base64
		$s3 = "!This program cannot be run in DOS mode." xor

	condition:
		$hvhd at 0 and any of ($s*) and filesize <=10MB
}