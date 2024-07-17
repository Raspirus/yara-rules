rule SIGNATURE_BASE_WEBSHELL_JSP_Nov21_1 : FILE
{
	meta:
		description = "Detects JSP webshells"
		author = "Florian Roth (Nextron Systems)"
		id = "117eed28-c44e-5983-b4c7-b555fc06d923"
		date = "2021-11-23"
		modified = "2023-12-05"
		reference = "https://www.ic3.gov/Media/News/2021/211117-2.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/expl_spring4shell.yar#L2-L17"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "1dac7706421961c71ba6f8d7a223b80e4b77bf206bfb64ee18c7cc894b062a3c"
		score = 70
		quality = 85
		tags = "FILE"

	strings:
		$x1 = "request.getParameter(\"pwd\")" ascii
		$x2 = "excuteCmd(request.getParameter(" ascii
		$x3 = "getRuntime().exec (request.getParameter(" ascii
		$x4 = "private static final String PW = \"whoami\"" ascii

	condition:
		filesize <400KB and 1 of them
}