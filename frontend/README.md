# Security Analysis Chat Interface

Giao diện chat hiện đại để phân tích log bảo mật với khả năng upload file.

## Tính năng

- 💬 Chat interface giống ChatGPT
- 📎 Upload file log (.log, .txt, .csv, .pdf)
- 🔍 Phân tích log tự động với LangGraph
- 📊 Hiển thị kết quả phân tích trực quan
- 📥 Download báo cáo CSV
- 🤖 Tích hợp RAG để trả lời câu hỏi bảo mật

## Cài đặt

### 1. Cài đặt dependencies

```bash
cd frontend
npm install
```

### 2. Chạy development server

```bash
npm run dev
```

Frontend sẽ chạy tại: http://localhost:3000

### 3. Đảm bảo backend đang chạy

```bash
# Từ thư mục gốc
python run_backend.py
```

Backend API sẽ chạy tại: http://localhost:8888

## Sử dụng

### Upload file và phân tích

1. Click vào icon 📎 để chọn file log
2. Nhập câu hỏi (tùy chọn): "Phân tích các cuộc tấn công SQL injection"
3. Click Send hoặc nhấn Enter
4. Xem kết quả phân tích

### Đặt câu hỏi trực tiếp

1. Nhập câu hỏi: "SQL injection là gì?"
2. Hệ thống sẽ trả lời từ knowledge base
3. Hoặc: "1 giờ qua có tấn công không?" → Tự động query Splunk

## API Endpoints

### POST /api/analyze-file
Upload và phân tích file log

**Request:**
- `file`: File upload (multipart/form-data)
- `query`: Câu hỏi về file (optional)

**Response:**
```json
{
  "findings_summary": {
    "total_events": 100,
    "total_attack_events": 15,
    "severity_level": "high",
    "attack_breakdown": [...]
  },
  "attack_events_ref": {
    "csv_path": "./output/attack_events_xxx.csv"
  },
  "report_markdown": "..."
}
```

### POST /api/smart-analyze
Phân tích với natural language query

**Request:**
```json
{
  "query": "1 giờ qua có tấn công SQL injection không?"
}
```

## Cấu trúc thư mục

```
frontend/
├── src/
│   ├── App.jsx          # Main component
│   ├── App.css          # Styles
│   ├── main.jsx         # Entry point
│   └── index.css        # Global styles
├── index.html
├── package.json
└── vite.config.js
```

## Build production

```bash
npm run build
```

Output sẽ ở thư mục `dist/`

## Troubleshooting

### CORS errors
Đảm bảo backend có CORS middleware enabled (đã có sẵn trong backend/main.py)

### API connection failed
Kiểm tra backend đang chạy tại http://localhost:8888

### File upload failed
Kiểm tra file size và format (.log, .txt, .csv, .pdf)
