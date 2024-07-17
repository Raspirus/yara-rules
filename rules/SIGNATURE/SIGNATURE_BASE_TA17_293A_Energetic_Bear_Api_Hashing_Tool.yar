rule SIGNATURE_BASE_TA17_293A_Energetic_Bear_Api_Hashing_Tool : FILE
{
	meta:
		description = "Energetic Bear API Hashing Tool"
		author = "CERT RE Team"
		id = "4e58800a-9618-5d8b-954c-e843be6002c2"
		date = "2024-02-29"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_ta17_293A.yar#L77-L93"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "5f8a770c727cdd2d32d7cd1ad45ee8b37f7fc63c9e7f4311d318eb15d9050909"
		score = 75
		quality = 85
		tags = "FILE"
		assoc_report = "DHS Report TA17-293A"

	strings:
		$api_hash_func_v1 = { 8A 08 84 C9 74 ?? 80 C9 60 01 CB C1 E3 01 03 45 10 EB ED }
		$api_hash_func_v2 = { 8A 08 84 C9 74 ?? 80 C9 60 01 CB C1 E3 01 03 44 24 14 EB EC }
		$api_hash_func_x64 = { 8A 08 84 C9 74 ?? 80 C9 60 48 01 CB 48 C1 E3 01 48 03 45 20 EB EA }
		$http_push = "X-mode: push" nocase
		$http_pop = "X-mode: pop" nocase

	condition:
		$api_hash_func_v1 or $api_hash_func_v2 or $api_hash_func_x64 and ( uint16(0)==0x5a4d or $http_push or $http_pop)
}