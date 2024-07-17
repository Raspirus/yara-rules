import "pe"


rule SIGNATURE_BASE_SUSP_PS1_Combo_Transfersh_Feb24 : SCRIPT
{
	meta:
		description = "Detects suspicious PowerShell command that downloads content from transfer.sh as often found in loaders"
		author = "Florian Roth"
		id = "fd14cca5-9cf8-540b-9d6e-39ca2c267272"
		date = "2024-02-23"
		modified = "2024-04-24"
		reference = "https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/expl_connectwise_screenconnect_vuln_feb24.yar#L120-L135"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "64d4343ecdcbc4a28571557bec2f31c1ff73c2ecf63d0feaa0a71001bb9bf499"
		score = 70
		quality = 85
		tags = "SCRIPT"

	strings:
		$x1 = ".DownloadString('https://transfer.sh"
		$x2 = ".DownloadString(\"https://transfer.sh"
		$x3 = "Invoke-WebRequest -Uri 'https://transfer.sh"
		$x4 = "Invoke-WebRequest -Uri \"https://transfer.sh"

	condition:
		1 of them
}