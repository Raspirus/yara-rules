rule SIGNATURE_BASE_SUSP_Doc_Wordxmlrels_May22 : CVE_2022_30190 FILE
{
	meta:
		description = "Detects a suspicious pattern in docx document.xml.rels file as seen in CVE-2022-30190 / Follina exploitation"
		author = "Tobias Michalski, Christian Burkard, Wojciech Cieslak"
		id = "304c4816-b2f6-5319-9fe9-8f74bdb82ad0"
		date = "2022-05-30"
		modified = "2022-06-20"
		reference = "https://doublepulsar.com/follina-a-microsoft-office-code-execution-vulnerability-1a47fce5629e"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_doc_follina.yar#L34-L56"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		hash = "62f262d180a5a48f89be19369a8425bec596bc6a02ed23100424930791ae3df0"
		logic_hash = "c9846f8c2c1724792de14ab4de0064f951a8faaf01cc27d873e600f29d59c842"
		score = 70
		quality = 85
		tags = "CVE-2022-30190, FILE"

	strings:
		$a1 = "<Relationships" ascii
		$a2 = "TargetMode=\"External\"" ascii
		$x1 = ".html!" ascii
		$x2 = ".htm!" ascii
		$x3 = "%2E%68%74%6D%6C%21" ascii
		$x4 = "%2E%68%74%6D%21" ascii

	condition:
		filesize <50KB and all of ($a*) and 1 of ($x*)
}