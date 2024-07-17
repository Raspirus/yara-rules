rule RUSSIANPANDA_Workersdevbackdoor_PS : FILE
{
	meta:
		description = "Detects WorkersDevBackdoor PowerShell script"
		author = "RussianPanda"
		id = "d2b526c1-a9f5-57de-818c-99b02e778a0d"
		date = "2023-12-15"
		modified = "2023-12-15"
		reference = "https://github.com/RussianPanda95/Yara-Rules"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/c65f3c62711bf141e4eb926ffe3a9880e5331974/WorkersDevBackdoor/WorkersDevBackdoor_PS.yar#L1-L18"
		license_url = "N/A"
		logic_hash = "c71eed8fd7a44f3018150cc6ef55d10779093ed8e4c77fd9babcf9b1b9fadfda"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "sleep" wide
		$s2 = "convertto-securestring" wide
		$s3 = "System.Drawing.dll" wide
		$s4 = "System.Web.Extensions.dll" wide
		$s5 = "System.Windows.Forms.dll" wide
		$s6 = "CSharp" wide

	condition:
		all of ($s*) and filesize <200KB
}