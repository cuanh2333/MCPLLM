# KB NGHIỆP VỤ TÀI SẢN (Internal Asset KB)

## 
* IP: 192.168.1.10 (IP Máy Chủ)
* **Nghiệp vụ (Label):** `SERVER` / `PROTECTED_ASSET` (Tài sản cần bảo vệ)
* **Logic (Rule):** Khi LLM phân tích log, nếu IP này là **MỤC TIÊU (Target)** của một cuộc tấn công (SQLi, XSS, Scan), đây là một cảnh báo **NGHIÊM TRỌNG (Critical)**.

## 
* IP: 192.168.96.144 (IP Máy Chủ)
* **Nghiệp vụ (Label):** `SERVER` / `PROTECTED_ASSET` (Tài sản cần bảo vệ)
* **Logic (Rule):** Khi LLM phân tích log, nếu IP này là **MỤC TIÊU (Target)** của một cuộc tấn công (SQLi, XSS, Scan), đây là một cảnh báo **NGHIÊM TRỌNG (Critical)**.

## 
* IP: 192.168.1.100 (IP Tấn Công / Pentest)
* **Nghiệp vụ (Label):** `PENTEST` / `AUTHORIZED_ATTACKER` (Tấn công được phép)
* **Logic (Rule):** Khi LLM phân tích log, nếu IP này là **NGUỒN (Source)** của một cuộc tấn công, đây là một hoạt động **GIẢ LẬP (Simulated)**. Mức độ nghiêm trọng là **THÔNG TIN (Informational)**.

## 
* IP: 192.168.96.1 (IP Tấn Công / Pentest)
* **Nghiệp vụ (Label):** `PENTEST` / `AUTHORIZED_ATTACKER` (Tấn công được phép)
* **Logic (Rule):** Khi LLM phân tích log, nếu IP này là **NGUỒN (Source)** của một cuộc tấn công, đây là một hoạt động **GIẢ LẬP (Simulated)**. Mức độ nghiêm trọng là **THÔNG TIN (Informational)**.

## 
* IP: 192.168.96.131 (IP Collector )
* **Nghiệp vụ (Label):** `Thua thập log` (Thường là thu thập log từ các web_server)
* **Logic (Rule):** Khi LLM phân tích log, nếu IP này là **NGUỒN (Source)** của một cuộc tấn công, đây là một hoạt động **Thu Thập (Simulated)**. Mức độ nghiêm trọng là **THÔNG TIN (Informational)**.

## 
* DVWA
* **Domain:** Đây là Domain mô phỏng các cuộc tấn công
* **Logic:** Khi LLM phân tích log, nếu Domain này là **MỤC TIÊU (target)** của một cuộc tấn công web, hãy coi như đây là 1 domain hợp lệ và vẫn hoạt động phân tích log một cách chi tiết.