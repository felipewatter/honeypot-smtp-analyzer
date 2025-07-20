# Honeypot SMTP Analyzer

🚨 Um servidor SMTP honeypot projetado para capturar, analisar e registrar tentativas de spam, phishing e ataques automatizados a serviços de e-mail.

![CI](https://github.com/felipewatter/honeypot-smtp-analyzer/actions/workflows/ci.yml/badge.svg)

## ✨ Funcionalidades

- Captura passiva de mensagens SMTP
- Análise heurística de links suspeitos
- Detecção de padrões de phishing
- Registro estruturado de tentativas em JSONL
- Preparado para integração com frontend e dashboards

## 📦 Tecnologias Utilizadas

- Python 3.11
- [aiosmtpd](https://aiosmtpd.readthedocs.io)
- regex, JSON, logging
- GitHub Actions (CI)
- FastAPI e Websockets (opcional)

## 🚀 Instalação

```bash
git clone https://github.com/felipewatter/honeypot-smtp-analyzer.git
cd honeypot-smtp-analyzer
pip install -r requirements.txt
```

## ▶️ Execução

```bash
python src/main.py
```

O servidor escutará na porta 25 por padrão.

> É necessário ter permissão de root ou redirecionar a porta se estiver em ambiente Linux.

## 📁 Estrutura do Projeto

```
src/
├── main.py                  # Entrada principal do honeypot
├── core/handler.py          # Handler SMTP personalizado
├── utils/analyzer.py        # Análise heurística de phishing
├── utils/logger.py          # Logger em JSONL
└── logs/attempts.jsonl      # Registro de tentativas
.github/
└── workflows/ci.yml         # Pipeline de CI
```

## 🧪 Testes

O projeto possui lint e validações básicas na pipeline CI. Em breve serão adicionados testes unitários.

## 📜 Licença

Distribuído sob a licença MIT. Veja `LICENSE` para mais informações.