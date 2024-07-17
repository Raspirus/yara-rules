
rule RUSSIANPANDA_Smartapesg_JS_Netsupportrat_Stage2 : FILE
{
	meta:
		description = "Detects SmartApeSG JavaScript Stage 2 retrieving NetSupportRAT"
		author = "RussianPanda"
		id = "2a614e11-be32-5bf1-9fd1-da224f0a644e"
		date = "2024-01-11"
		modified = "2024-01-12"
		reference = "https://github.com/RussianPanda95/Yara-Rules"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/c65f3c62711bf141e4eb926ffe3a9880e5331974/SmartApeSG/SmartApeSG_JS_NetSupportRAT_stage2.yar#L1-L23"
		license_url = "N/A"
		hash = "67d8f84b37732cf85e05b327ad6b6a9f"
		logic_hash = "5a2afaa14d513e0a3c4e52acfb433e53a4541983a05d15318a217c14dc06453c"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$x1 = "powershell.exe -Ex Bypass -NoP -C $"
		$x2 = "Get-Random -Minimum -1000 -Maximum 1000"
		$s1 = "HKCU:\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run"
		$s2 = "=new ActiveXObject('W"
		$s3 = "System.Net.WebClient).DownloadString($"
		$s4 = "FromBase64String"
		$s5 = "Start-Process -FilePath $"

	condition:
		filesize <1MB and ((1 of ($x*) and 3 of them ) or 5 of them )
}