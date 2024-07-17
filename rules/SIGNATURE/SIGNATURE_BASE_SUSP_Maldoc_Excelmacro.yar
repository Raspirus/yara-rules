rule SIGNATURE_BASE_SUSP_Maldoc_Excelmacro : FILE
{
	meta:
		description = "Detects malicious Excel macro Artifacts"
		author = "James Quinn"
		id = "76806717-a9a8-520e-b6b6-7718eb088de5"
		date = "2020-11-03"
		modified = "2023-12-05"
		reference = "YARA Exchange - Undisclosed Macro Builder"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_macro_builders.yar#L2-L19"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "c5d0655eaf2ca36c828675f9673a1d4284ef8719fd9ec1d354ee3284d1fb0a0c"
		score = 65
		quality = 85
		tags = "FILE"

	strings:
		$artifact1 = {5c 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 2e 00 ?? 00 ?? 00}
		$url1 = "http://" wide
		$url2 = "https://" wide
		$import1 = "URLDownloadToFileA" wide ascii
		$macro = "xl/macrosheets/"

	condition:
		uint16(0)==0x4b50 and filesize <2000KB and $artifact1 and $macro and $import1 and 1 of ($url*)
}