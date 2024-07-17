
rule SIGNATURE_BASE_LOG_CVE_2021_27065_Exchange_Forensic_Artefacts_Mar21_2 : LOG
{
	meta:
		description = "Detects suspicious log entries that indicate requests as described in reports on HAFNIUM activity"
		author = "Florian Roth (Nextron Systems)"
		id = "37a26def-b360-518e-a4ab-9604a5b39afd"
		date = "2021-03-10"
		modified = "2023-12-05"
		reference = "https://www.praetorian.com/blog/reproducing-proxylogon-exploit/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_hafnium_log_sigs.yar#L92-L104"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "13e2e46689bc0e87c3cf13dc2ce213c384afe6c03c21e62a467974a0518c12da"
		score = 65
		quality = 85
		tags = "LOG"

	strings:
		$sr1 = /GET \/rpc\/ &CorrelationID=<empty>;&RequestId=[^\n]{40,600} (200|301|302)/

	condition:
		$sr1
}