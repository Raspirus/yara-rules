
rule SIGNATURE_BASE_SUSP_Doc_RTF_Externalresource_May22 : CVE_2022_30190 FILE
{
	meta:
		description = "Detects a suspicious pattern in RTF files which downloads external resources as seen in CVE-2022-30190 / Follina exploitation"
		author = "Tobias Michalski, Christian Burkard"
		id = "71bb97e0-ec12-504c-a1f6-25039ac91c86"
		date = "2022-05-30"
		modified = "2022-05-31"
		reference = "https://doublepulsar.com/follina-a-microsoft-office-code-execution-vulnerability-1a47fce5629e"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_doc_follina.yar#L58-L74"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "c841e0c1ff78bf8dade5f573a7452b16a7f447cfc19417704b727684a8f3d3ff"
		score = 70
		quality = 85
		tags = "CVE-2022-30190, FILE"

	strings:
		$s1 = " LINK htmlfile \"http" ascii
		$s2 = ".html!\" " ascii

	condition:
		uint32be(0)==0x7B5C7274 and filesize <300KB and all of them
}