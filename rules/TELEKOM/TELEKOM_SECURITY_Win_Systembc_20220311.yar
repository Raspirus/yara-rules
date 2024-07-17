rule TELEKOM_SECURITY_Win_Systembc_20220311 : FILE
{
	meta:
		description = "Detects unpacked SystemBC module"
		author = "Thomas Barabosch, Deutsche Telekom Security"
		id = "39e1a131-bd2c-56e9-961f-2b2c31f29e85"
		date = "2022-03-13"
		modified = "2022-03-13"
		reference = "https://medium.com/walmartglobaltech/inside-the-systembc-malware-as-a-service-9aa03afd09c6"
		source_url = "https://github.com/telekom-security/malware_analysis//blob/bf832d97e8fd292ec5e095e35bde992a6462e71c/systembc/systembc.yara#L1-L27"
		license_url = "N/A"
		logic_hash = "2f6e2c4c786941f800678e22679d4b81d1097a46c2555ae70e745df1b997c1c8"
		score = 75
		quality = 70
		tags = "FILE"
		sharing = "TLP:WHITE"
		hash_1 = "c926338972be5bdfdd89574f3dc2fe4d4f70fd4e24c1c6ac5d2439c7fcc50db5"
		in_memory = "True"

	strings:
		$sx1 = "-WindowStyle Hidden -ep bypass -file" ascii
		$sx2 = "BEGINDATA" ascii
		$sx3 = "GET %s HTTP/1.0" ascii
		$s5 = "User-Agent:" ascii
		$s8 = "ALLUSERSPROFILE" ascii

	condition:
		( uint16(0)==0x5a4d and filesize <30KB and 2 of ($sx*)) or all of them
}