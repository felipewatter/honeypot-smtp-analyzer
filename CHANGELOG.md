# Changelog

## 0.2.0 — 2026-10-31

- Corrigido o hook SMTP com handle_DATA compatível com aiosmtpd.
- Análise offline de MIME multipart com limites de processamento e extração de domínios.
- Registro somente de metadados, logs JSONL privados e proteção contra symlinks.
- Listener seguro em 127.0.0.1:2525; bind externo requer opção explícita.
- Controles de limite de mensagem, comandos e tempo ocioso.
- Pacote instalável, testes unitários/SMTP reais e CI multiplataforma.
- Removidas dependências não utilizadas; aiosmtpd fixado na versão 1.4.6.

## 0.1.0

- Protótipo inicial sem testes de recepção SMTP.

- Nota de compatibilidade: integração SMTP em macOS não validada nos runners GitHub; matriz obrigatória limita-se a Ubuntu e Windows até resolução.
