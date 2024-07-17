import "pe"


rule SIGNATURE_BASE_MAL_Floxif_Generic : FILE
{
	meta:
		description = "Detects Floxif Malware"
		author = "Florian Roth (Nextron Systems)"
		id = "5ddd6a6c-b02a-518b-bbe3-8f528b3d7eae"
		date = "2018-05-11"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/crime_floxif_flystudio.yar#L3-L18"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "1996f717100d9f1abc2ed3f1e9d0c55daec09654c0f99987ddaea9e9f0d17008"
		score = 80
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "de055a89de246e629a8694bde18af2b1605e4b9b493c7e4aef669dd67acf5085"

	condition:
		uint16(0)==0x5a4d and filesize <200KB and (pe.imphash()=="2f4ddcfebbcad3bacadc879747151f6f" or pe.exports("FloodFix") or pe.exports("FloodFix2"))
}