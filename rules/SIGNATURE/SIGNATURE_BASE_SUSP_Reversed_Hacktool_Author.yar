
rule SIGNATURE_BASE_SUSP_Reversed_Hacktool_Author : FILE
{
	meta:
		description = "Detects a suspicious path traversal into a Windows folder"
		author = "Florian Roth (Nextron Systems)"
		id = "33e20d75-af07-5df2-82c3-c48aec37a947"
		date = "2020-06-10"
		modified = "2023-12-05"
		reference = "https://hackingiscool.pl/cmdhijack-command-argument-confusion-with-path-traversal-in-cmd-exe/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_susp_obfuscation.yar#L85-L99"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "3681fb11dabf9905915d23f4198145b503a260d628415fd79ad71d7703ba9f6f"
		score = 65
		quality = 85
		tags = "FILE"

	strings:
		$x1 = "iwiklitneg" fullword ascii wide
		$x2 = " eetbus@ " ascii wide

	condition:
		filesize <4000KB and 1 of them
}