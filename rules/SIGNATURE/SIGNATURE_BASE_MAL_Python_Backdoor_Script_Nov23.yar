
rule SIGNATURE_BASE_MAL_Python_Backdoor_Script_Nov23 : CVE_2023_4966 FILE
{
	meta:
		description = "Detects a trojan (written in Python) that communicates with c2 - was seen being used by LockBit 3.0 affiliates exploiting CVE-2023-4966"
		author = "X__Junior"
		id = "861f9ce3-3c54-5c56-b50b-2b7536783f6e"
		date = "2023-11-23"
		modified = "2023-12-05"
		reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-325a"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_ransom_lockbit_citrixbleed_nov23.yar#L56-L71"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "b336f6438a420af49b1b0144039f1051f12c0c54f77a94e2f947f71d1f6230b3"
		score = 80
		quality = 85
		tags = "CVE-2023-4966, FILE"
		hash1 = "906602ea3c887af67bcb4531bbbb459d7c24a2efcb866bcb1e3b028a51f12ae6"

	strings:
		$s1 = "port = 443 if \"https\"" ascii
		$s2 = "winrm.Session basic error" ascii
		$s3 = "Windwoscmd.run_cmd(str(cmd))" ascii

	condition:
		filesize <50KB and all of them
}