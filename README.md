# Xây dựng hệ thống AI WAF cho web học tiếng Anh trực tuyến

Đồ án môn An toàn và Bảo mật thông tin.

Hệ thống là một tường lửa ứng dụng web (Web Application Firewall) ba lớp có tích hợp học máy, đặt trước nền tảng học tiếng Anh trực tuyến EngPro theo mô hình reverse proxy. Hệ thống chặn các tấn công web phổ biến mà không phải chỉnh sửa mã nguồn của EngPro, đồng thời hạn chế tối đa việc chặn nhầm nội dung hợp lệ của người dùng.

- Sinh viên thực hiện: Trần Đinh Danh — 23010211
- Giảng viên hướng dẫn: Đoàn Trung Sơn

## Mục lục

1. [Giới thiệu](#1-giới-thiệu)
2. [Bài toán](#2-bài-toán)
3. [Kiến trúc hệ thống](#3-kiến-trúc-hệ-thống)
4. [Ba lớp phát hiện](#4-ba-lớp-phát-hiện)
5. [Kết quả thực nghiệm](#5-kết-quả-thực-nghiệm)
6. [Công nghệ sử dụng](#6-công-nghệ-sử-dụng)
7. [Cấu trúc thư mục](#7-cấu-trúc-thư-mục)
8. [Cài đặt và chạy](#8-cài-đặt-và-chạy)
9. [Kịch bản demo](#9-kịch-bản-demo)
10. [Kiểm thử](#10-kiểm-thử)
11. [Thông tin đồ án](#11-thông-tin-đồ-án)

## 1. Giới thiệu

EngPro là một nền tảng học và luyện thi ba chứng chỉ IELTS, TOEIC và TOEFL. Đây là một ứng dụng web hoàn chỉnh với đăng nhập, xác thực hai lớp, thanh toán VNPay, trợ lý AI và khoảng 120 API, phục vụ ba vai trò học viên, giảng viên và quản trị viên. Vì là một web thật với bề mặt tấn công đầy đủ, EngPro có nhu cầu bảo vệ thật.

AI WAF được xây dựng như một dịch vụ độc lập đứng trước EngPro. Mọi request của người dùng đi vào WAF trước; WAF kiểm tra qua ba lớp rồi mới quyết định cho đi tiếp hay chặn lại. Nhờ tách rời, WAF bảo vệ được ứng dụng mà không cần sửa một dòng mã nào của EngPro, và có thể dùng lại để bảo vệ những ứng dụng khác.

## 2. Bài toán

Một WAF truyền thống chỉ dựa trên luật (biểu thức chính quy) gặp hai điểm yếu:

- Dễ bị né tránh: kẻ tấn công thay đổi biến thể, ví dụ `UnIoN/**/SeLeCt` thay cho `UNION SELECT`, là có thể vượt qua các luật đơn giản.
- Hay chặn nhầm: để bắt được nhiều biến thể, luật phải viết rộng, và khi đó nó chặn cả nội dung hợp lệ.

Vấn đề chặn nhầm đặc biệt nghiêm trọng với một web học tiếng Anh. Học viên thường xuyên gõ những câu chứa từ khóa trông giống tấn công, ví dụ "In SQL we write SELECT name FROM students" trong bài Writing. Một WAF chặn nhầm sẽ khiến học viên không nộp được bài.

Đồ án giải quyết bằng cách kết hợp luật với một mô hình học máy hiểu được ngữ cảnh, nhằm đạt đồng thời hai mục tiêu: phát hiện tấn công cao và báo nhầm gần như bằng không.

## 3. Kiến trúc hệ thống

AI WAF hoạt động như một reverse proxy: nhận request ở cổng 8000, kiểm tra, rồi chuyển tiếp các request hợp lệ sang EngPro ở cổng 8080.

```
          Người dùng / Kẻ tấn công
                     │
                     ▼  cổng 8000
          AI WAF  (reverse proxy, Python)
             ├─ Lớp 1 · Luật & chữ ký (regex)
             ├─ Lớp 2 · Học máy (TF-IDF + Logistic Regression)
             └─ Lớp 3 · Hành vi bất thường (theo IP)
                     │
      sạch → chuyển tiếp   │   độc hại → trả 403 + ghi log
                     ▼  cổng 8080
          EngPro  (chỉ nhận kết nối từ 127.0.0.1)
```

Điểm thiết kế quan trọng:

- Không thể đi vòng: khi bật `TRUST_PROXY=1`, EngPro chỉ nhận kết nối từ máy nội bộ, nên từ bên ngoài mọi request buộc phải đi qua WAF.
- Độc lập công nghệ: cùng một mã nguồn WAF bảo vệ được cả EngPro (Node.js) lẫn DVWA (PHP) dùng cho thực nghiệm.
- Giám sát được: mọi request, dù cho qua hay bị chặn, đều được ghi vào nhật ký và hiển thị trên dashboard thời gian thực.

## 4. Ba lớp phát hiện

Ba lớp chạy theo thứ tự từ nhanh và chắc chắn đến tốn kém và mềm dẻo. Lớp nào kết luận độc hại thì chặn ngay.

| Lớp | Kỹ thuật | Nhiệm vụ | Ưu điểm |
|---|---|---|---|
| Lớp 1 — Luật & chữ ký | 29 biểu thức chính quy | Bắt các tấn công có mẫu rõ ràng: SQLi, XSS, Path Traversal, Command Injection, Template Injection, công cụ quét, đường dẫn nhạy cảm | Nhanh (khoảng 0.02 ms), chắc chắn, giải thích được lý do chặn |
| Lớp 2 — Học máy | TF-IDF trên n-gram ký tự + Logistic Regression | Chấm điểm rủi ro 0–1 (ngưỡng chặn 0.80), bắt các biến thể mà luật bỏ sót | Hiểu ngữ cảnh nên không chặn nhầm câu tiếng Anh |
| Lớp 3 — Hành vi | Đếm tần suất theo địa chỉ IP | Phát hiện dò mật khẩu và quét / DoS tầng ứng dụng | Bắt được tấn công mà từng request trông bình thường |

## 5. Kết quả thực nghiệm

Các số liệu dưới đây được đo trực tiếp trên hệ thống.

### Chặn khai thác thật (trên bia tập chuẩn DVWA)

| Lỗ hổng | Gửi thẳng DVWA (không WAF) | Gửi qua AI WAF |
|---|---|---|
| SQL Injection `' OR '1'='1` | Lấy được 5 tài khoản người dùng | Bị chặn (403) |
| XSS phản chiếu | Mã chèn vào chạy được trong trình duyệt | Bị chặn (403) |
| Số lỗ hổng khai thác thành công | 2 / 2 | 0 / 2 |

### Hiệu quả trên chính EngPro

| Chỉ tiêu | Kết quả |
|---|---|
| Tấn công bị chặn | 13 / 13 |
| Báo nhầm trên lưu lượng bình thường | 0 / 10 |

### So sánh với ModSecurity + OWASP CRS

| WAF | Phát hiện tấn công | Báo nhầm câu tiếng Anh | Độ trễ p50 |
|---|---|---|---|
| AI WAF (đồ án) | 20 / 20 (100%) | 0 / 19 (0%) | 1.1 ms |
| ModSecurity PL1 (mặc định) | 19 / 20 (95%) | 1 / 19 (5%) | 1.9 ms |
| ModSecurity PL2 (gắt hơn) | 20 / 20 (100%) | 6 / 19 (32%) | 1.8 ms |

### Mô hình học máy và hiệu năng

| Chỉ tiêu | Kết quả |
|---|---|
| F1 trên payload chưa từng thấy | 0.956 (precision 1.000, báo nhầm 0) |
| Độ trễ WAF thêm vào mỗi request | khoảng 1–3 ms |
| Tự kiểm thử an toàn của chính WAF | 10 / 10 bài đạt |

## 6. Công nghệ sử dụng

| Thành phần | Công nghệ |
|---|---|
| AI WAF | Python, FastAPI, uvicorn, httpx, scikit-learn, SQLite |
| Dashboard | HTML, Chart.js |
| EngPro (web được bảo vệ) | Node.js, Express, PostgreSQL |
| Thực nghiệm | DVWA, ModSecurity + OWASP CRS (chạy bằng Docker) |

## 7. Cấu trúc thư mục

```
.
├── ai-waf/                 Hệ thống AI WAF — trọng tâm đồ án
│   ├── app/                Reverse proxy và ba lớp phát hiện
│   ├── ml/                 Dữ liệu, huấn luyện và mô hình học máy
│   ├── tests/              Kịch bản demo, so sánh, kiểm thử an toàn
│   ├── static/             Dashboard giám sát
│   └── README.md           Hướng dẫn chi tiết của AI WAF
├── server.js               EngPro — máy chủ Express, toàn bộ API
├── js/  pages/  db/        EngPro — giao diện, trang, cơ sở dữ liệu
├── ENGPRO.md               Mô tả chi tiết hệ thống EngPro
└── README.md               Tài liệu này
```

## 8. Cài đặt và chạy

Yêu cầu: Node.js 20 trở lên, Python 3.11 trở lên, PostgreSQL (hoặc Docker).

```bash
# 1. Chạy EngPro (web được bảo vệ) — cổng 8080
npm install
TRUST_PROXY=1 npm run dev

# 2. Chạy AI WAF — cổng 8000
cd ai-waf
./run.sh
```

Sau khi chạy:

- Truy cập EngPro qua WAF: http://localhost:8000
- Dashboard giám sát: http://localhost:8000/waf/dashboard

## 9. Kịch bản demo

Bật toàn bộ hệ thống demo (EngPro, hai tiến trình WAF, DVWA, ModSecurity) bằng một lệnh, cần mở Docker trước:

```bash
cd ai-waf
./demo.sh start        # bật toàn bộ
./demo.sh status       # xem trạng thái
./demo.sh stop         # tắt toàn bộ
```

So sánh trước và sau khi có WAF:

```bash
python -m tests.demo_attack --direct   # gửi thẳng EngPro, tấn công lọt
python -m tests.demo_attack            # gửi qua WAF, tấn công bị chặn
python -m tests.demo_dvwa --direct     # khai thác thật trên DVWA
python -m tests.demo_dvwa              # khai thác bị WAF chặn
```

## 10. Kiểm thử

```bash
python -m tests.test_security      # kiểm thử an toàn của chính WAF (10/10)
python -m tests.compare_modsec     # so sánh với ModSecurity + OWASP CRS
python -m tests.compare_layers     # so sánh lớp luật và lớp học máy
python -m tests.bench_latency      # đo độ trễ WAF thêm vào
python -m ml.train                 # huấn luyện lại mô hình, in precision/recall/F1
```

Hướng dẫn chi tiết hơn về từng kịch bản nằm trong [ai-waf/README.md](ai-waf/README.md).

## 11. Thông tin đồ án

| | |
|---|---|
| Tên đề tài | Xây dựng hệ thống AI WAF cho web học tiếng Anh trực tuyến |
| Môn học | An toàn và Bảo mật thông tin |
| Sinh viên thực hiện | Trần Đinh Danh — 23010211 |
| Giảng viên hướng dẫn | Đoàn Trung Sơn |
