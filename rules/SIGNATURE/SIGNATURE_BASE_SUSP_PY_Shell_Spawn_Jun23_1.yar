rule SIGNATURE_BASE_SUSP_PY_Shell_Spawn_Jun23_1 : SCRIPT
{
	meta:
		description = "Detects suspicious one-liner to spawn a shell using Python"
		author = "Florian Roth"
		id = "15fd2c9a-c425-5d4d-9209-fd3826074d6c"
		date = "2023-06-15"
		modified = "2023-12-05"
		reference = "https://www.mandiant.com/resources/blog/barracuda-esg-exploited-globally"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_barracuda_esg_unc4841_jun23.yar#L119-L131"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "63e94447930d5a00399de753076facbfb2bf18dd8c815f01aaefd14678aea034"
		score = 70
		quality = 85
		tags = "SCRIPT"

	strings:
		$x1 = "python -c import pty;pty.spawn(\"/bin/" ascii

	condition:
		1 of them
}