rule SIGNATURE_BASE_APT_Turlamosquito_MAL_Oct22_1 : FILE
{
	meta:
		description = "Detects Turla Mosquito malware"
		author = "Florian Roth (Nextron Systems)"
		id = "f5ad0c0f-81ca-5157-aefb-ead049ada30d"
		date = "2022-10-25"
		modified = "2023-12-05"
		reference = "https://www.welivesecurity.com/wp-content/uploads/2018/01/ESET_Turla_Mosquito.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_turla_mosquito.yar#L129-L156"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "fbaca774d6398aac7c171a5d87aa456a1921c1b80449d06f392b088db33ee845"
		score = 80
		quality = 85
		tags = "FILE"
		hash1 = "6b9e48e3f4873cfb95639d9944fe60e3b056daaa2ea914add14c982e3e11128b"
		hash2 = "b868b674476418bbdffbe0f3d617d1cce4c2b9dae0eaf3414e538376523e8405"
		hash3 = "e7fd14ca45818044690ca67f201cc8cfb916ccc941a105927fc4c932c72b425d"

	strings:
		$s1 = "Logger32.dll" ascii fullword
		$s4 = " executing %u command on drive %martCommand : CWin32ApiErrorExce" wide
		$s5 = "Unsupported drive!!!" ascii fullword
		$s7 = "D:\\Build_SVN\\PC_MAGICIAN_4." ascii fullword
		$op1 = { 40 cc 8b 8b 06 cc 55 00 70 8b 10 10 33 51 04 46 04 64 }
		$op2 = { c3 10 e8 50 04 00 cc ff 8d 00 69 8d 75 ff 68 ec 6a 4d }
		$op3 = { e8 64 a1 6e 00 64 a1 c2 04 08 75 40 73 1d 8b ff cc 10 89 cc 8b c3 cc af }

	condition:
		uint16(0)==0x5a4d and filesize <2000KB and (pe.imphash()=="073235ae6dfbb1bf5db68a039a7b7726" or all of them )
}