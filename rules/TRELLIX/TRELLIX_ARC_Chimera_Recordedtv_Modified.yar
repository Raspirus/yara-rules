
rule TRELLIX_ARC_Chimera_Recordedtv_Modified : TROJAN FILE
{
	meta:
		description = "Rule to detect the modified version of RecordedTV.ms found in the Operation Skeleton"
		author = "Marc Rivero | McAfee ATR Team"
		id = "b0969713-41a4-550c-9545-f02783fa8d02"
		date = "2020-04-21"
		modified = "2020-08-14"
		reference = "https://medium.com/@cycraft_corp/taiwan-high-tech-ecosystem-targeted-by-foreign-apt-group-5473d2ad8730"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/APT/APT_operation_skeleton.yar#L1-L33"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		hash = "66f13964c87fc6fe093a9d8cc0de0bf2b3bdaea9564210283fdb97a1dde9893b"
		logic_hash = "7165779b66999259a079fa68f898c5f9fb634adcb9d249366d321dff1014184b"
		score = 75
		quality = 70
		tags = "TROJAN, FILE"
		rule_version = "v1"
		malware_type = "trojan"
		malware_family = "Trojan:W32/RecordedTV"
		actor_type = "Apt"
		actor_group = "Unknown"

	strings:
		$byte = { C0 0E 5B C3 }
		$s1 = "Encrypted file:  CRC failed in %s (password incorrect ?)" fullword wide
		$s2 = "EBorland C++ - Copyright 1999 Inprise Corporation" fullword ascii
		$s3 = " MacOS file type:  %c%c%c%c  ; " fullword wide
		$s4 = "rar.lng" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <900KB and all of them
}