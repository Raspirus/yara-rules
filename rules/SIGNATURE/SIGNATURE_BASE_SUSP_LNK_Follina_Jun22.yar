
rule SIGNATURE_BASE_SUSP_LNK_Follina_Jun22 : CVE_2022_30190 FILE
{
	meta:
		description = "Detects LNK files with suspicious Follina/CVE-2022-30190 strings"
		author = "Paul Hager"
		id = "d331d584-2ab3-5275-b435-6129c7291417"
		date = "2022-06-02"
		modified = "2023-12-05"
		reference = "https://twitter.com/gossithedog/status/1531650897905950727"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_doc_follina.yar#L239-L257"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "0b63bb266b968987b2b5a83c9429e96acbd57e12178e4f5fd5894b23d1aaa237"
		score = 75
		quality = 85
		tags = "CVE-2022-30190, FILE"

	strings:
		$sa1 = "msdt.exe" ascii wide
		$sa2 = "msdt " ascii wide
		$sa3 = "ms-msdt:" ascii wide
		$sb = "IT_BrowseForFile=" ascii wide

	condition:
		filesize <5KB and uint16(0)==0x004c and uint32(4)==0x00021401 and 1 of ($sa*) and $sb
}