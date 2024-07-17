rule SIGNATURE_BASE_SUSP_Msdt_Artefact_Jun22_2 : CVE_2022_30190 FILE
{
	meta:
		description = "Detects suspicious pattern in msdt diagnostics log (e.g. CVE-2022-30190 / Follina exploitation)"
		author = "Christian Burkard"
		id = "aa2a4bd7-2094-5652-a088-f58d0c7d3f62"
		date = "2022-06-01"
		modified = "2022-07-29"
		reference = "https://twitter.com/nas_bench/status/1531718490494844928"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_doc_follina.yar#L218-L237"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "e18f6405f0411128335336e65dda4ed2b6be6e9ad47b94646ececf0479fbe967"
		score = 75
		quality = 85
		tags = "CVE-2022-30190, FILE"

	strings:
		$a1 = "<ScriptError><Data id=\"ScriptName\" name=\"Script\">TS_ProgramCompatibilityWizard.ps1" ascii
		$x1 = "/../../" ascii
		$x2 = "$(Invoke-Expression" ascii
		$x3 = "$(IEX(" ascii nocase

	condition:
		uint32(0)==0x6D783F3C and $a1 and 1 of ($x*)
}