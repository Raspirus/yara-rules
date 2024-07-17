import "pe"


rule SIGNATURE_BASE_HKTL_Sqlmap_Backdoor : FILE
{
	meta:
		description = "Detects SqlMap backdoors"
		author = "Florian Roth (Nextron Systems)"
		id = "bf09caac-cf15-5936-b5b4-df4f28788961"
		date = "2018-10-09"
		modified = "2023-12-05"
		reference = "https://github.com/sqlmapproject/sqlmap"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/thor-hacktools.yar#L4527-L4543"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "5e09135e3908442d873511b7b75c8475b2345a28f3bad41a242d6fc5a3b7c002"
		score = 75
		quality = 85
		tags = "FILE"

	condition:
		( uint32(0)==0x8e859c07 or uint32(0)==0x2d859c07 or uint32(0)==0x92959c07 or uint32(0)==0x929d9c07 or uint32(0)==0x29959c07 or uint32(0)==0x2b8d9c07 or uint32(0)==0x2b859c07 or uint32(0)==0x28b59c07) and filesize <2KB
}