
rule SIGNATURE_BASE_APT_UNC2447_BAT_Runner_May21_1 : FILE
{
	meta:
		description = "Detects Batch script runners from UNC2447 campaign"
		author = "Florian Roth (Nextron Systems)"
		id = "0bacd4f7-421a-570f-9f74-5a19ab806dd0"
		date = "2021-05-01"
		modified = "2023-01-07"
		reference = "https://www.fireeye.com/blog/threat-research/2021/04/unc2447-sombrat-and-fivehands-ransomware-sophisticated-financial-threat.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_unc2447_sombrat.yar#L121-L135"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "f9872327f648e4421aa40ca3ce55df5d3eb5e8c5bc718ff62a3d4adac79217eb"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "ccacf4658ae778d02e4e55cd161b5a0772eb8b8eee62fed34e2d8f11db2cc4bc"

	strings:
		$x1 = "powershell.exe -c \"[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String([IO.File]::" ascii
		$x2 = "wwansvc.txt')))\" | powershell.exe -" ascii

	condition:
		filesize <5000KB and 1 of them
}