rule SIGNATURE_BASE_APT_HKTL_Proxy_Tool_Jun23_1 : FILE
{
	meta:
		description = "Detects agent used as proxy tool in UNC4841 intrusions - possibly Alchemist C2 framework implant"
		author = "Florian Roth"
		id = "0e406737-3083-53c2-a6d2-14c07794125a"
		date = "2023-06-16"
		modified = "2023-12-05"
		reference = "https://www.mandiant.com/resources/blog/barracuda-esg-exploited-globally"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_barracuda_esg_unc4841_jun23.yar#L76-L101"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "7e2152e1aa74e1842519e2eecd2acd3ef8eb8d517f3c0ef9f05c983616f223c3"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "ca72fa64ed0a9c22d341a557c6e7c1b6a7264b0c4de0b6f717dd44bddf550bca"
		hash2 = "57e4b180fd559f15b59c43fb3335bd59435d4d76c4676e51a06c6b257ce67fb2"

	strings:
		$a2 = "/src/runtime/panic.go"
		$s1 = "main.handleClientRequest" ascii fullword
		$s2 = "main.sockIP.toAddr" ascii fullword

	condition:
		( uint16(0)==0x5a4d or uint32be(0)==0x7f454c46 or uint16(0)==0xfeca or uint16(0)==0xfacf or uint32(0)==0xbebafeca or uint32(0)==0xbebafeca) and filesize <10MB and all of them
}