rule SIGNATURE_BASE_Turlamosquito_Mal_4 : FILE
{
	meta:
		description = "Detects malware sample from Turla Mosquito report"
		author = "Florian Roth (Nextron Systems)"
		id = "1d5c32b3-0316-525c-9386-222917144251"
		date = "2018-02-22"
		modified = "2023-12-05"
		reference = "https://www.welivesecurity.com/wp-content/uploads/2018/01/ESET_Turla_Mosquito.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_turla_mosquito.yar#L79-L90"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "4765b912258491f38c03513204d9af8bc62c37df2fe583e371cbbeff6fc12298"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "b362b235539b762734a1833c7e6c366c1b46474f05dc17b3a631b3bff95a5eec"

	condition:
		uint16(0)==0x5a4d and filesize <800KB and pe.imphash()=="17b328245e2874a76c2f46f9a92c3bad"
}