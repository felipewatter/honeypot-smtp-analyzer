# Honeypot SMTP Analyzer

[![CI](https://github.com/felipewatter/honeypot-smtp-analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/felipewatter/honeypot-smtp-analyzer/actions/workflows/ci.yml)

Honeypot SMTP não-relay em Python. Recebe mensagens de teste ou de pesquisa autorizada, analisa texto e HTML sem visitar URLs externas e registra apenas metadados em JSONL.

## Requisitos

Python 3.11, 3.12 ou 3.13. A única dependência de execução é aiosmtpd==1.4.6. A instalação não exige FastAPI, GeoIP ou banco de dados.

## Instalação

    git clone https://github.com/felipewatter/honeypot-smtp-analyzer.git
    cd honeypot-smtp-analyzer
    python -m venv .venv
    # Ative o ambiente virtual com o comando do seu sistema
    python -m pip install -e .

## Inicialização (segura por padrão)

    smtp-honeypot --host 127.0.0.1 --port 2525 --log-file ./logs/attempts.jsonl

Alternativa no checkout: python src/main.py

Teste local com Python (somente para uso autorizado):

    python -c "import smtplib; s=smtplib.SMTP('127.0.0.1',2525,timeout=5); s.sendmail('lab@example.test',['honeypot@example.test'],'Subject: lab\n\nSee https://example.test/login'); s.quit()"

Para ler o JSONL, que contém uma linha JSON por evento:

    python -c "import json; [print(json.loads(x)) for x in open('logs/attempts.jsonl', encoding='utf-8')]"

O sistema **não guarda corpo, assunto em texto claro ou URLs completas**. Os campos incluem timestamp, IP, domínios do envelope, SHA-256 da mensagem e do assunto, domínios de links e indicadores heurísticos. IPs devem ser tratados conforme a política de privacidade e retenção aplicável.

## Argumentos

| Opção | Padrão | Finalidade |
|---|---|---|
| --host | 127.0.0.1 | Interface de rede |
| --port | 2525 | Porta não privilegiada |
| --log-file | logs/attempts.jsonl | Caminho do JSONL |
| --max-message-bytes | 262144 | Limite de 256 KiB por mensagem |
| --allow-public-bind | desligado | Autoriza escuta em interfaces não locais |

Executar em 0.0.0.0 sem --allow-public-bind falha de forma segura.

**Importante:** Expor um honeypot na Internet requer permissão, infraestrutura isolada, firewall e contenção de tráfego de saída. Não é um MTA de produção.

## Arquitetura

1. aiosmtpd recebe sessão SMTP, sem encaminhar ou entregar e-mails.
2. HoneypotHandler.handle_DATA coleta bytes da mensagem e os analisa sem executar HTML nem consultar URLs.
3. O analisador processa partes text/plain e text/html MIME; ignora anexos e limita a leitura de texto e quantidade de links.
4. O logger grava uma linha JSONL em arquivo com permissão 0600 (POSIX). Falhas de persistência retornam resposta SMTP 451, sem sucesso falso.

**Heurísticas:** links associados a credenciais, hosts IP, domínios Punycode, usuário/senha na URL e excesso de links. Não são diagnósticos definitivos de phishing.

## Testes

    python -m pip install -e .
    python -m unittest discover -s tests -v
    python -m compileall -q src
    smtp-honeypot --help

GitHub Actions valida Linux, macOS e Windows com Python 3.11, 3.12 e 3.13. Dependabot monitora dependências e Actions.

Licença MIT. Para divulgação privada de falhas, veja SECURITY.md.
