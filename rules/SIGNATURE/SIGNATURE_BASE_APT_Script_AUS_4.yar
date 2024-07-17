rule SIGNATURE_BASE_APT_Script_AUS_4 : FILE
{
	meta:
		description = "Detetcs a script involved in the Australian Parliament House network compromise"
		author = "Florian Roth (Nextron Systems)"
		id = "5cbf2476-5ce8-540d-b87b-e400daf49b43"
		date = "2019-02-18"
		modified = "2023-12-05"
		reference = "https://twitter.com/cyb3rops/status/1097423665472376832"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_aus_parl_compromise.yar#L73-L90"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "3a81365572380964abe07a1ec16a9ea299bf16a4e624285faaa6f72c44f762d2"
		score = 75
		quality = 83
		tags = "FILE"
		hash1 = "fdf15f388a511a63fbad223e6edb259abdd4009ec81fcc87ce84f0f2024c8057"

	strings:
		$x1 = "myMutex = CreateMutex(0, 1, \"teX23stNew\")" fullword ascii
		$x2 = "mmpath = Environ(appdataPath) & \"\\\" & \"Microsoft\" & \"\\\" & \"mm.accdb\"" fullword ascii
		$x3 = "Dim mmpath As String, newmmpath  As String, appdataPath As String" fullword ascii
		$x4 = "'MsgBox \"myMutex Created\" Do noting" fullword ascii
		$x5 = "appdataPath = \"app\" & \"DatA\"" fullword ascii
		$x6 = ".DoCmd.Close , , acSaveYes" fullword ascii

	condition:
		filesize <7KB and 1 of them
}