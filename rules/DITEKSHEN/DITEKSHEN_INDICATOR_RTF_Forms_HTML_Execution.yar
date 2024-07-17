
rule DITEKSHEN_INDICATOR_RTF_Forms_HTML_Execution : FILE
{
	meta:
		description = "detects RTF files with Forms.HTML:Image.1 or Forms.HTML:Submitbutton.1 OLE objects referencing file or HTTP URLs."
		author = "ditekSHen"
		id = "26b21c94-9192-53be-808b-b553f87769e1"
		date = "2024-02-22"
		modified = "2024-02-22"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_office.yar#L494-L508"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "5e8a2072971c40d6fbc0e0265a9adfbe4faa04d0f3c6962fda443da33aa06906"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$img_clsid = "12d11255c65ccf118d6700aa00bdce1d" ascii nocase
		$sub_clsid = "10d11255c65ccf118d6700aa00bdce1d" ascii nocase
		$http_url = "6800740074007000" ascii nocase
		$file_url = "660069006c0065003a" ascii nocase

	condition:
		uint32(0)==0x74725c7b and filesize <1500KB and ($img_clsid or $sub_clsid) and ($http_url or $file_url)
}