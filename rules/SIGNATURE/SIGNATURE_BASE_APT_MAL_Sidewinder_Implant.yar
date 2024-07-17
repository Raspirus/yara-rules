
rule SIGNATURE_BASE_APT_MAL_Sidewinder_Implant : FILE
{
	meta:
		description = "Detects SideWinder final payload"
		author = "AT&T Alien Labs"
		id = "3a420c9c-7821-5405-8d4d-6931d0f311ba"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://cybersecurity.att.com/blogs/labs-research/a-global-perspective-of-the-sidewinder-apt"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_sidewinder.yar#L24-L50"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "bfad86dbdc04463e7e4cc126fd05fc9107617a7ea1bd3f283c0e0170862bd59b"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "c568238dcf1e30d55a398579a4704ddb8196b685"

	strings:
		$code = { 1B 30 05 00 C7 00 00 00 00 00 00 00 02 28 03 00
               00 06 7D 12 00 00 04 02 02 FE 06 23 00 00 06 73
               5B 00 00 0A 14 20 88 13 00 00 15 73 5C 00 00 0A
               7D 13 00 00 04 02 02 FE 06 24 00 00 06 73 5B 00
               00 0A 14 20 88 13 00 00 15 73 5C 00 00 0A 7D 15
               00 00 04 02 7B 12 00 00 04 6F 0E 00 00 06 2C 1D
               02 28 1F 00 00 06 02 7B 12 00 00 04 16 6F 0F 00
               00 06 02 7B 12 00 00 04 6F 06 00 00 06 02 7B 12
               00 00 04 6F 10 00 00 06 2C 23 02 28 20 00 00 06
               02 28 21 00 00 06 02 7B 12 00 00 04 16 }
		$strings = { 
         2E 00 73 00 69 00 66 00 00 09 2E 00 66 00 6C 00
         63 00 00 1B 73 00 65 00 6C 00 65 00 63 00 74 00
         65 00 64 00 46 00 69 00 6C 00 65 00 73
      }

	condition:
		uint16(0)==0x5A4D and all of them
}