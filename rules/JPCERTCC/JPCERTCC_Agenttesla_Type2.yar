
rule JPCERTCC_Agenttesla_Type2 : FILE
{
	meta:
		description = "detect Agenttesla in memory"
		author = "JPCERT/CC Incident Response Group"
		id = "6a0b8075-4a7a-56e8-99d2-794340fd1f8b"
		date = "2021-08-16"
		modified = "2021-08-16"
		reference = "internal research"
		source_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/yara/rule.yara#L413-L427"
		license_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/LICENSE.txt"
		logic_hash = "22f0a7e8f542aa1861f580a2ec3fb2b58ff0ac5d1c606ced0d207a3c350c3633"
		score = 75
		quality = 80
		tags = "FILE"
		rule_usage = "memory scan"
		hash1 = "670a00c65eb6f7c48c1e961068a1cb7fd3653bd29377161cd04bf15c9d010da2 "

	strings:
		$type2db1 = "1.85 (Hash, version 2, native byte-order)" wide
		$type2db2 = "Unknow database format" wide
		$type2db3 = "SQLite format 3" wide
		$type2db4 = "Berkelet DB" wide

	condition:
		( uint16(0)==0x5A4D) and 3 of them
}