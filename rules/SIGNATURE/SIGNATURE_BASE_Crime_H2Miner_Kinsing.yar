
rule SIGNATURE_BASE_Crime_H2Miner_Kinsing : FILE
{
	meta:
		description = "Rule to find Kinsing malware"
		author = "Tony Lambert, Red Canary"
		id = "1cabca0d-7134-517e-b82e-f2b20b4d1c34"
		date = "2020-06-09"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/crime_h2miner_kinsing.yar#L1-L20"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "8795f01f4ce85ca37a4e4667a4ee9756dae6af42884cf79830877a5c35a3bd3b"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "-iL $INPUT --rate $RATE -p$PORT -oL $OUTPUT"
		$s2 = "libpcap"
		$s3 = "main.backconnect"
		$s4 = "main.masscan"
		$s5 = "main.checkHealth"
		$s6 = "main.redisBrute"
		$s7 = "ActiveC2CUrl"
		$s8 = "main.RC4"
		$s9 = "main.runTask"

	condition:
		( uint32(0)==0x464C457F) and filesize >1MB and all of them
}