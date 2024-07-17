rule SIGNATURE_BASE_EXPL_Zoho_RCE_Fix_Lines_Dec21_1 : FILE
{
	meta:
		description = "Detects lines in log lines of Zoho products that indicate RCE fixes (silent removal of evidence)"
		author = "Florian Roth (Nextron Systems)"
		id = "633287e3-a377-5b3c-8520-a7790168eff5"
		date = "2021-12-06"
		modified = "2023-12-05"
		reference = "https://twitter.com/cyb3rops/status/1467784104930385923"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_zoho_rcef_logs.yar#L2-L27"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "e6d9c3364da57c03a5e838f485deefabec2f3ec67d19a9017e564ba702a72d03"
		score = 65
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "RCEF="
		$sa1 = "\"attackStatus\"\\:\"active\""
		$sa2 = "\"attackStatus\":\"active\""
		$sd1 = "deletedCount"
		$sd_fp1 = "\"deletedCount\"\\:0"
		$sd_fp2 = "\"deletedCount\":0"

	condition:
		filesize <6MB and $s1 and (1 of ($sa*) or ($sd1 and not 1 of ($sd_fp*)))
}