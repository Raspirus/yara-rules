
rule TRELLIX_ARC_Karkoff_Dnspionaje : BACKDOOR FILE
{
	meta:
		description = "Rule to detect the Karkoff malware"
		author = "Marc Rivero | McAfee ATR Team"
		id = "a5cdc65f-3a4c-5d97-9d88-8d60b14dfb9a"
		date = "2019-04-23"
		modified = "2020-08-14"
		reference = "https://blog.talosintelligence.com/2019/04/dnspionage-brings-out-karkoff.html"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/APT/APT_karkoff_dnspionaje.yar#L1-L30"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		hash = "5b102bf4d997688268bab45336cead7cdf188eb0d6355764e53b4f62e1cdf30c"
		logic_hash = "79dd0087f1197cb1b2cd98416302363951479ba5ebf82289768585b56ed21c3a"
		score = 75
		quality = 70
		tags = "BACKDOOR, FILE"
		rule_version = "v1"
		malware_type = "backdoor"
		malware_family = "Backdoor:W32/Karkoff"
		actor_type = "Apt"
		actor_group = "Unknown"

	strings:
		$s1 = "DropperBackdoor.Newtonsoft.Json.dll" fullword wide
		$s2 = "C:\\Windows\\Temp\\MSEx_log.txt" fullword wide
		$s3 = "DropperBackdoor.exe" fullword wide
		$s4 = "get_ProcessExtensionDataNames" fullword ascii
		$s5 = "get_ProcessDictionaryKeys" fullword ascii
		$s6 = "https://www.newtonsoft.com/json 0" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and all of them
}