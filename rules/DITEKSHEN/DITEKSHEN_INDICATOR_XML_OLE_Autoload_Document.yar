
rule DITEKSHEN_INDICATOR_XML_OLE_Autoload_Document : FILE
{
	meta:
		description = "detects AutoLoad documents using OLE Object"
		author = "ditekSHen"
		id = "b3d682c3-641a-554a-8607-e99d07e9a57d"
		date = "2024-02-22"
		modified = "2024-02-22"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_office.yar#L571-L581"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "b262a9f8e82dea55afc26acac731827b64f52069a2bf314f716832b3dfc2c04f"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "autoLoad=\"true\"" ascii
		$s2 = "/relationships/oleObject\"" ascii
		$s3 = "Target=\"../embeddings/oleObject" ascii

	condition:
		uint32(0)==0x6d783f3c and all of ($s*)
}