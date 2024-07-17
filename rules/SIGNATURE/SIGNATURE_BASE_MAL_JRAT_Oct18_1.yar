rule SIGNATURE_BASE_MAL_JRAT_Oct18_1 : FILE
{
	meta:
		description = "Detects JRAT malware"
		author = "Florian Roth (Nextron Systems)"
		id = "f211ef1c-8def-55f0-8817-d01ebd9c2947"
		date = "2018-10-11"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_rats_malwareconfig.yar#L1060-L1072"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "7c652f3943ae7639633b82663f639adb7dea1bae9e617a14710fb6e448cfdbee"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "ce190c37a6fdb2632f4bc5ea0bb613b3fbe697d04e68e126b41910a6831d3411"

	strings:
		$x1 = "/JRat.class" ascii

	condition:
		uint16(0)==0x4b50 and filesize <700KB and 1 of them
}