
rule SIGNATURE_BASE_SUSP_Dropperbackdoor_Keywords : FILE
{
	meta:
		description = "Detects suspicious keywords that indicate a backdoor"
		author = "Florian Roth (Nextron Systems)"
		id = "2942ba6d-a533-5954-bfcf-417262e2fac2"
		date = "2019-04-24"
		modified = "2023-12-05"
		reference = "https://blog.talosintelligence.com/2019/04/dnspionage-brings-out-karkoff.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_suspicious_strings.yar#L302-L314"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "e83fa95bb2b9ac821d0a00af23834495066ad2cad38ef4f4dcc81aee75415d74"
		score = 65
		quality = 85
		tags = "FILE"
		hash1 = "cd4b9d0f2d1c0468750855f0ed352c1ed6d4f512d66e0e44ce308688235295b5"

	strings:
		$x4 = "DropperBackdoor" fullword wide ascii

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and 1 of them
}