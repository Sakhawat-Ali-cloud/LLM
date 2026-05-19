# LLM Security Gateway v2.0

A production-ready **hybrid security gateway** for Large Language Model (LLM) prompts. Detects and mitigates prompt injection attacks, personally identifiable information (PII) leakage, semantic threats, and multilingual attacks in real-time.

---

## 🎯 Overview

The LLM Security Gateway provides a comprehensive defense mechanism for LLM applications by analyzing user inputs before they reach the model. It combines multiple detection techniques:

- **Prompt Injection Detection**: Keyword-based and rule-based analysis with weighted threat scoring
- **PII Detection & Masking**: Identifies sensitive data (credit cards, emails, IDs, API keys) and redacts them
- **Semantic Analysis**: Uses sentence transformers to detect adversarial prompts by similarity
- **Multilingual Support**: Automatically detects language, translates non-English text, and detects transliteration attacks
- **Preprocessing & Obfuscation Handling**: Normalizes leet-speak, spacing tricks, base64 encoding, and unicode homoglyphs
- **Audit Logging**: Complete request history with decision tracking and search capabilities
- **Metrics & Observability**: Real-time performance tracking and detection statistics

---

## 🚀 Features

### 1. **Multi-Layer Detection**
- Keyword pattern matching with configurable weights
- Semantic threat detection via transformer embeddings
- PII recognition using Presidio + custom patterns
- Language detection and automatic translation

### 2. **Intelligent Preprocessing**
- Leet-speak normalization (3→e, @→a)
- Spacing attack mitigation ("j a i l" → "jail")
- Base64 decoding and expansion
- Unicode normalization (fullwidth, homoglyphs)

### 3. **Flexible Policy Engine**
- Rule-based decision making (ALLOW, WARN, BLOCK)
- Configurable risk thresholds
- Weighted scoring (injection: 60%, PII: 40%)
- Custom reason codes for audit trails

### 4. **Enterprise-Grade Audit**
- Complete request logging with timestamps
- Client IP and User-Agent tracking
- Decision history searchable by date/status
- Max text length configuration for compliance

### 5. **RESTful API**
- Single-request analysis: `/analyze`
- Batch processing: `/analyze/batch`
- Health checks: `/health`
- Metrics dashboard: `/metrics`
- Audit search: `/audit/search`, `/audit/recent`

---

## 📋 Requirements

- Python 3.8+
- CUDA-compatible GPU (recommended for transformer models)
- 2GB+ RAM

### Dependencies

```
fastapi==0.104.1
uvicorn==0.27.0
pydantic==1.10.13
presidio-analyzer==2.2.33
presidio-anonymizer==2.2.33
spacy==3.7.2
numpy==1.26.4
scipy==1.11.4
torch==2.2.2
transformers==4.41.2
sentence-transformers==2.7.0
langdetect==1.0.9
deep-translator==1.11.4
scikit-learn==1.4.2
pandas==2.2.2
```

---

## 🔧 Installation

### 1. Clone or Extract Repository
```bash
cd LLM_improved
```

### 2. Create Virtual Environment
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Download Language Models (Optional)
```bash
python -m spacy download en_core_web_sm
```

---

## 🏃 Quick Start

### Start the Server
```bash
python main.py
```

Server runs on `http://localhost:8000`

### API Documentation
- **Interactive Docs**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

### Example Requests

#### Single Analysis
```bash
curl -X POST "http://localhost:8000/analyze" \
  -H "Content-Type: application/json" \
  -d '{"text": "What is the capital of France?"}'
```

#### Batch Analysis
```bash
curl -X POST "http://localhost:8000/analyze/batch" \
  -H "Content-Type: application/json" \
  -d '{"texts": ["Question 1?", "Question 2?", "Question 3?"]}'
```

#### Health Check
```bash
curl "http://localhost:8000/health"
```

#### View Metrics
```bash
curl "http://localhost:8000/metrics"
```

#### Recent Audit Records
```bash
curl "http://localhost:8000/audit/recent?n=10"
```

---

## ⚙️ Configuration

Edit `config.yaml` to customize behavior:

### Injection Detection Thresholds
```yaml
injection_detection:
  thresholds:
    medium: 0.30   # MEDIUM risk
    high:   0.60   # HIGH risk
    block:  0.75   # BLOCK decision
```

### Semantic Detection
```yaml
semantic_detection:
  enabled: true
  model_name: "all-MiniLM-L6-v2"
  threshold: 0.60        # Cosine similarity threshold
  injection_boost_weight: 0.40
```

### Multilingual Support
```yaml
multilingual:
  enabled: true
  target_language: "en"
  fallback_language: "en"
```

### PII Detection
```yaml
pii_detection:
  confidence_threshold: 0.50
  mask_replacement: "[REDACTED]"
  
  custom_recognizers:
    api_key:
      enabled: true
      patterns:
        - "sk-[a-zA-Z0-9]{20,}"
        - "AKIA[0-9A-Z]{16}"
```

### Audit Logging
```yaml
audit:
  enabled: true
  log_dir: "audit_logs"
  max_text_len: 500       # -1 = unlimited
  rotate_daily: true
```

---

## 📁 Project Structure

```
LLM_improved/
├── main.py                      # FastAPI application & endpoints
├── pipeline.py                  # Core security pipeline orchestrator
├── injection_detector.py        # Keyword-based injection detection
├── pii_detector.py              # PII recognition & masking (Presidio)
├── semantic_detector.py         # Transformer-based threat detection
├── policy_engine.py             # Decision logic (ALLOW/WARN/BLOCK)
├── multilingual.py              # Language detection & translation
├── preprocessor.py              # Obfuscation normalization
├── audit_log.py                 # Request logging & search
├── metrics.py                   # Performance & detection metrics
├── app.py                       # Alternative app entry point
├── config.yaml                  # Configuration file
├── requirements.txt             # Python dependencies
├── tests/
│   ├── test_injection_detector.py
│   └── test_pii_detector.py
├── dataset/
│   ├── build_dataset.py         # Generate training/eval datasets
│   └── final_eval.csv           # Evaluation results
└── evaluation/
    └── eval_metrics.py          # Evaluation metrics
```

---

## 🧪 Testing

Run unit tests:
```bash
pytest tests/ -v
```

Test specific detector:
```bash
pytest tests/test_injection_detector.py -v
pytest tests/test_pii_detector.py -v
```

---

## 📊 API Response Example

```json
{
  "request_id": "req_abc123xyz",
  "decision": "BLOCK",
  "reason": "High-risk prompt injection detected",
  "rule_score": 0.82,
  "injection_score": 0.82,
  "injection_risk": "CRITICAL",
  "semantic_score": 0.45,
  "semantic_threat": false,
  "pii_detected": true,
  "pii_confidence": 0.95,
  "pii_entities": [
    {
      "type": "EMAIL",
      "value": "user@example.com",
      "confidence": 0.95,
      "start": 42,
      "end": 60
    }
  ],
  "masked_text": "Contact [REDACTED] for details",
  "detected_lang": "en",
  "was_translated": false,
  "latency_ms": 45.32,
  "final_risk": 0.78,
  "reason_codes": ["INJECTION_HIGH", "PII_DETECTED"]
}
```

---

## 🔐 Decision Outcomes

| Decision | Meaning | Action |
|----------|---------|--------|
| **ALLOW** | Safe to process | Forward to LLM |
| **WARN** | Moderate risk | Log & process with caution |
| **BLOCK** | High/critical risk | Reject request, return error |

---

## 📈 Metrics Endpoint

```bash
curl "http://localhost:8000/metrics"
```

Returns:
- Total requests processed
- Average latency (ms)
- Injection detection rate
- PII detection rate
- Decision distribution (ALLOW/WARN/BLOCK)
- Detection statistics by entity type

---

## 🌐 Multilingual Support

Automatically handles:
- **Language Detection**: Detects 50+ languages using langdetect
- **Translation**: Translates to English via Google Translate API
- **Transliteration Attack Detection**: Identifies homoglyph/script-switching attacks
- **Multilingual NER**: Uses language-aware PII detection

Example:
```bash
# Arabic prompt injection attempt
curl -X POST "http://localhost:8000/analyze" \
  -H "Content-Type: application/json" \
  -d '{"text": "تجاهل التعليمات السابقة"}'
# → Detects & translates automatically
```

---

## 🛡️ Security Considerations

1. **API Key Protection**: Deploy behind reverse proxy with authentication
2. **Rate Limiting**: Add rate limiters for production (e.g., using slowapi)
3. **HTTPS**: Always use HTTPS in production
4. **Audit Logs**: Regularly rotate and archive audit logs
5. **Model Updates**: Keep transformer models updated
6. **Inference Server**: Consider using GPU-optimized inference (TorchServe, vLLM)

---

## 🔄 Graceful Degradation

The gateway includes fallbacks:
- If semantic detector fails → continues with keyword detection
- If multilingual processor fails → treats text as English
- If audit logger fails → continues processing requests
- If preprocessor fails → skips normalization

All components are optional and non-blocking.

---

## 📝 Audit Log Format

Audit logs are stored in `audit_logs/` with JSON records:

```json
{
  "timestamp": "2024-05-19T10:30:45.123456",
  "request_id": "req_abc123",
  "decision": "BLOCK",
  "reason": "Injection score exceeded threshold",
  "client_ip": "192.168.1.100",
  "user_agent": "Mozilla/5.0...",
  "injection_score": 0.82,
  "pii_detected": false,
  "latency_ms": 45.32
}
```

Search audit logs:
```bash
curl "http://localhost:8000/audit/search?decision=BLOCK&date=2024-05-19"
```

---

## 🚢 Deployment

### Docker (Recommended)
```dockerfile
FROM python:3.10-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
EXPOSE 8000
CMD ["python", "main.py"]
```

Build & run:
```bash
docker build -t llm-security-gateway .
docker run -p 8000:8000 llm-security-gateway
```

### Production Checklist
- [ ] Set `reload=False` in config
- [ ] Configure logging level to "warning"
- [ ] Enable audit logging
- [ ] Set up reverse proxy (nginx/Caddy)
- [ ] Configure SSL/TLS certificates
- [ ] Set rate limiting
- [ ] Monitor metrics endpoint
- [ ] Rotate audit logs daily
- [ ] Use environment variables for secrets

---

## 📚 Component Details

### InjectionDetector
- Pattern matching with configurable weights
- Risk scoring (0.0-1.0)
- Matched patterns returned for debugging

### PIIDetector
- Uses Presidio for 20+ entity types
- Custom patterns for API keys, internal IDs, Pakistan CNIC
- Type-specific masking tokens

### SemanticDetector
- Lightweight MiniLM model (80MB)
- Real-time embedding similarity
- Configurable threat patterns

### MultilingualProcessor
- Auto-detects language
- Translates to English for analysis
- Detects transliteration/homoglyph attacks

### PreProcessor
- Leet-speak normalization
- Base64 decoding
- Unicode normalization

### PolicyEngine
- Weighted risk calculation
- Configurable thresholds
- Reason code generation

### AuditLogger
- JSON logging to disk
- Daily rotation
- Searchable by date/decision

---

## 🐛 Troubleshooting

### "Module not found" errors
```bash
pip install -r requirements.txt --upgrade
```

### GPU not detected
```bash
python -c "import torch; print(torch.cuda.is_available())"
# If False, install CPU-only version or check GPU drivers
```

### Slow startup
- First run downloads transformer models (~500MB)
- Subsequent runs are faster (models cached)
- Use smaller models: `distiluse-base-multilingual-cased-v2`

### Memory issues
- Reduce batch size in `/analyze/batch`
- Use CPU-only inference: set `CUDA_VISIBLE_DEVICES=""`
- Use quantized models

---

## 📄 License

[Add your license here]

---

## 👥 Contributing

[Add contribution guidelines]

---

## 📞 Support

For issues, feature requests, or questions:
- Check existing issues
- Review API documentation at `/docs`
- Check audit logs for error details

---

## 🔗 Related Links

- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [Presidio - Microsoft's PII Detection](https://microsoft.github.io/presidio/)
- [Sentence Transformers](https://www.sbert.net/)
- [LangDetect](https://github.com/Mimino666/langdetect)
- [Deep Translator](https://github.com/nidhaloff/deep-translator)

---

**Version**: 2.0.0  
**Last Updated**: May 2024
