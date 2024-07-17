import "pe"


rule SIGNATURE_BASE_MAL_Trickbot_Oct19_3 : FILE
{
	meta:
		description = "Detects Trickbot malware"
		author = "Florian Roth (Nextron Systems)"
		id = "3428b7e3-def9-5574-bbbb-6ba98c134dec"
		date = "2019-10-02"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/crime_trickbot.yar#L40-L56"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "87860212077b63bf3e4835a3a64b934fc7edd3258355a3e94a69acaba39c2516"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "25a4ae2a1ce6dbe7da4ba1e2559caa7ed080762cf52dba6c8b55450852135504"
		hash2 = "57b8ea2870f5176a30e6cba2d717fb3ff342f8bd36bac652dc4194a313b5fa64"
		hash3 = "d75561a744e3ed45dfbf25fe7c120bd24c38138ac469fd02e383dd455a540334"
		hash4 = "57b8ea2870f5176a30e6cba2d717fb3ff342f8bd36bac652dc4194a313b5fa64"
		hash5 = "e92dd00b092b435420f0996e4f557023fe1436110a11f0f61fbb628b959aac99"

	strings:
		$s1 = "Decrypt Shell Fail" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <=2000KB and (1 of them or pe.imphash()=="4e3fbfbf1fc23f646cd40a6fe09385a7")
}