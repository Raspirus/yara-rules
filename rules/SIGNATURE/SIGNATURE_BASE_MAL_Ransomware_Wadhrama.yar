import "pe"


rule SIGNATURE_BASE_MAL_Ransomware_Wadhrama : FILE
{
	meta:
		description = "Detects Wadhrama Ransomware via Imphash"
		author = "Florian Roth (Nextron Systems)"
		id = "f7de40e9-fe22-5f14-abc6-f6611a4382ac"
		date = "2019-04-07"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/crime_mal_ransom_wadharma.yar#L3-L13"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "5d78837ed7cb8914be0990859751cf64603ee5a5ad135541c60c6ae145046412"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "557c68e38dce7ea10622763c10a1b9f853c236b3291cd4f9b32723e8714e5576"

	condition:
		uint16(0)==0x5a4d and pe.imphash()=="f86dec4a80961955a89e7ed62046cc0e"
}