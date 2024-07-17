
rule SIGNATURE_BASE_SUSP_Win32Dll_String : FILE
{
	meta:
		description = "Detects suspicious string in executables"
		author = "Florian Roth (Nextron Systems)"
		id = "b1c78386-c23d-5138-942a-3da90e5802cc"
		date = "2018-10-24"
		modified = "2023-12-05"
		reference = "https://medium.com/@Sebdraven/apt-sidewinder-changes-theirs-ttps-to-install-their-backdoor-f92604a2739"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_suspicious_strings.yar#L220-L232"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "514596e078483920cedf0091cd769d8462acfd39956c3ed3e12d630b02ebb7cc"
		score = 65
		quality = 85
		tags = "FILE"
		hash1 = "7bd7cec82ee98feed5872325c2f8fd9f0ea3a2f6cd0cd32bcbe27dbbfd0d7da1"

	strings:
		$s1 = "win32dll.dll" fullword ascii

	condition:
		filesize <60KB and all of them
}