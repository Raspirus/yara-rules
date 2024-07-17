import "pe"


rule DITEKSHEN_INDICATOR_TOOL_PWS_Sniffpass : FILE
{
	meta:
		description = "Detects SniffPass, a password monitoring software that listens on the network and captures passwords over POP3, IMAP4, SMTP, FTP, and HTTP."
		author = "ditekSHen"
		id = "b96498d4-bbe3-5cb8-9c24-91ebb51e078a"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L197-L212"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "9b56ee4bac39b4220b24e92d00076650ffe84b71a60c0213a84fcf21c6cfe4cf"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "\\Release\\SniffPass.pdb" ascii
		$s2 = "Password   Sniffer" fullword wide
		$s3 = "Software\\NirSoft\\SniffPass" fullword ascii
		$s4 = "Sniffed PasswordsCFailed to start" wide
		$s5 = "Pwpcap.dll" fullword ascii
		$s6 = "nmwifi.exe" fullword ascii
		$s7 = "NmApi.dll" fullword ascii
		$s8 = "npptools.dll" fullword ascii

	condition:
		uint16(0)==0x5a4d and 4 of them
}