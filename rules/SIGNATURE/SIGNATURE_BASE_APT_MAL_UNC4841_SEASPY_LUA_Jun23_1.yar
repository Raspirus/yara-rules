
rule SIGNATURE_BASE_APT_MAL_UNC4841_SEASPY_LUA_Jun23_1 : FILE
{
	meta:
		description = "Detects SEASPY malware related LUA script"
		author = "Florian Roth"
		id = "a44861d0-107e-589b-8cf1-3fbc2f5c78dc"
		date = "2023-06-16"
		modified = "2023-12-05"
		reference = "https://blog.talosintelligence.com/alchimist-offensive-framework/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_barracuda_esg_unc4841_jun23.yar#L57-L74"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "f78823a4ba9e025ba4833a2d5234c7baba33c1167c0247f13b8b2baa430aa4e5"
		score = 90
		quality = 85
		tags = "FILE"
		hash1 = "56e8066bf83ff6fe0cec92aede90f6722260e0a3f169fc163ed88589bffd7451"

	strings:
		$x1 = "os.execute('rverify'..' /tmp/'..attachment:filename())" ascii fullword
		$x2 = "log.debug(\"--- opening archive [%s], mimetype [%s]\", tmpfile" ascii fullword
		$xe1 = "os.execute('rverify'..' /tmp/'..attachment:filename())" ascii base64
		$xe2 = "log.debug(\"--- opening archive [%s], mimetype [%s]\", tmpfile" ascii base64

	condition:
		filesize <500KB and 1 of them
}