import "pe"


rule SIGNATURE_BASE_MAL_Trickbot_Oct19_2 : FILE
{
	meta:
		description = "Detects Trickbot malware"
		author = "Florian Roth (Nextron Systems)"
		id = "2ff69a51-d089-53e5-ab19-4fbdf20f90f8"
		date = "2019-10-02"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/crime_trickbot.yar#L24-L38"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "185e59c156218b418bec0c94144b19639c17e3a9595d993e3761eae15379f9fb"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "57b8ea2870f5176a30e6cba2d717fb3ff342f8bd36bac652dc4194a313b5fa64"
		hash2 = "d75561a744e3ed45dfbf25fe7c120bd24c38138ac469fd02e383dd455a540334"

	strings:
		$x1 = "C:\\Users\\User\\Desktop\\Encrypt\\Math_Cad\\Release\\Math_Cad.pdb" fullword ascii
		$x2 = "AxedWV3OVTFfnGb" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <=2000KB and 1 of them
}