import "pe"


rule SIGNATURE_BASE_MAL_EXE_Royalransomware : FILE
{
	meta:
		description = "Detection for Royal Ransomware seen Dec 2022"
		author = "Silas Cutler, modfied by Florian Roth"
		id = "f83316f7-b8c4-5907-a38e-80535215e7ef"
		date = "2023-01-03"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_100days_of_yara_2023.yar#L197-L222"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		hash = "a8384c9e3689eb72fa737b570dbb53b2c3d103c62d46747a96e1e1becf14dfea"
		logic_hash = "6f93bade7709945b478cbdc721d85ad9243d56ace19fba25835cec13a6210dfb"
		score = 75
		quality = 85
		tags = "FILE"
		version = "1.0"
		DaysofYARA = "3/100"

	strings:
		$x_ext = ".royal_" wide
		$x_fname = "royal_dll.dll"
		$s_readme = "README.TXT" wide
		$s_cli_flag01 = "-networkonly" wide
		$s_cli_flag02 = "-localonly" wide
		$x_ransom_msg01 = "If you are reading this, it means that your system were hit by Royal ransomware."
		$x_ransom_msg02 = "Try Royal today and enter the new era of data security!"
		$x_onion_site = "http://royal2xthig3ou5hd7zsliqagy6yygk2cdelaxtni2fyad6dpmpxedid.onion/"

	condition:
		uint16(0)==0x5A4D and (2 of ($x*) or 5 of them )
}