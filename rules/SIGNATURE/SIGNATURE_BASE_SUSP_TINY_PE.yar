rule SIGNATURE_BASE_SUSP_TINY_PE : FILE
{
	meta:
		description = "Detects Tiny PE file"
		author = "Florian Roth (Nextron Systems)"
		id = "5081c24e-91d1-5705-9459-f675be4f0e3c"
		date = "2019-10-23"
		modified = "2023-12-05"
		reference = "https://webserver2.tecgraf.puc-rio.br/~ismael/Cursos/YC++/apostilas/win32_xcoff_pe/tyne-example/Tiny%20PE.htm"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_file_anomalies.yar#L3-L15"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "5eabfa8e0fd4d6d1376d263484fba985e7a4b05d68046be1f79c1dfdbbfff9e5"
		score = 80
		quality = 85
		tags = "FILE"

	strings:
		$header = { 4D 5A 00 00 50 45 00 00 }

	condition:
		uint16(0)==0x5a4d and uint16(4)==0x4550 and filesize <=20KB and $header at 0
}