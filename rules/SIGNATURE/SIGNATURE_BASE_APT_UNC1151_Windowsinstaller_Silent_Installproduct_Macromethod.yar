
rule SIGNATURE_BASE_APT_UNC1151_Windowsinstaller_Silent_Installproduct_Macromethod : FILE
{
	meta:
		description = "No description has been set in the source file - Signature Base"
		author = "Proofpoint Threat Research"
		id = "9ae80d54-33b9-55d7-957f-0738243e089f"
		date = "2021-07-28"
		modified = "2023-12-05"
		reference = "Thttps://www.proofpoint.com/us/blog/threat-insight/asylum-ambuscade-state-actor-uses-compromised-private-ukrainian-military-emails"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_unc1151_ua.yar#L1-L16"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "aec1bb992061fdf1abf5c1a61cf9ec9e54c1f13be36ceb84890b058ade273b70"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "1561ece482c78a2d587b66c8eaf211e806ff438e506fcef8f14ae367db82d9b3"
		hash2 = "a8fd0a5de66fa39056c0ddf2ec74ccd38b2ede147afa602aba00a3f0b55a88e0"

	strings:
		$doc_header = {D0 CF 11 E0 A1 B1 1A E1}
		$s1 = ".UILevel = 2"
		$s2 = "CreateObject(\"WindowsInstaller.Installer\")"
		$s3 = ".InstallProduct \"http"

	condition:
		$doc_header at 0 and all of ($s*)
}