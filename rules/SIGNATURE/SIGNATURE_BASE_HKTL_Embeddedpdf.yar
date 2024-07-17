import "pe"


rule SIGNATURE_BASE_HKTL_Embeddedpdf : FILE
{
	meta:
		description = "Detects Embedded PDFs which can start malicious content"
		author = "Tobias Michalski"
		id = "d4e2d878-fb75-54c5-9879-fe94102911d1"
		date = "2018-07-25"
		modified = "2023-12-05"
		reference = "https://twitter.com/infosecn1nja/status/1021399595899731968?s=12"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/thor-hacktools.yar#L4465-L4482"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "041580406e2a7c644d713d8fbf7fccb81664ff536e62df26b3c0f331409fb993"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$x1 = "/Type /Action\n /S /JavaScript\n /JS (this.exportDataObject({" fullword ascii
		$s1 = "(This PDF document embeds file" fullword ascii
		$s2 = "/Names << /EmbeddedFiles << /Names" fullword ascii
		$s3 = "/Type /EmbeddedFile" fullword ascii

	condition:
		uint16(0)==0x5025 and 2 of ($s*) and $x1
}