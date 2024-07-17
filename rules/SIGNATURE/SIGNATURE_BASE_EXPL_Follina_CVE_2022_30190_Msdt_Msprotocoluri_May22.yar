
rule SIGNATURE_BASE_EXPL_Follina_CVE_2022_30190_Msdt_Msprotocoluri_May22 : CVE_2022_30190 FILE
{
	meta:
		description = "Detects the malicious usage of the ms-msdt URI as seen in CVE-2022-30190 / Follina exploitation"
		author = "Tobias Michalski, Christian Burkard"
		id = "62e67c25-a420-5dac-9d1c-b0648ea6b574"
		date = "2022-05-30"
		modified = "2022-07-18"
		reference = "https://doublepulsar.com/follina-a-microsoft-office-code-execution-vulnerability-1a47fce5629e"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_doc_follina.yar#L76-L94"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "d56820737951f97606749c74025589e6a8ecbe70cfff069492368b2ba8528a7d"
		score = 80
		quality = 85
		tags = "CVE-2022-30190, FILE"
		hash1 = "4a24048f81afbe9fb62e7a6a49adbd1faf41f266b5f9feecdceb567aec096784"
		hash2 = "778cbb0ee4afffca6a0b788a97bc2f4855ceb69ddc5eaa230acfa2834e1aeb07"

	strings:
		$re1 = /location\.href\s{0,20}=\s{0,20}"ms-msdt:/
		$a1 = "%6D%73%2D%6D%73%64%74%3A%2F" ascii

	condition:
		filesize >3KB and filesize <100KB and 1 of them
}