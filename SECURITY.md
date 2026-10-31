# Política de Segurança

Para relatar vulnerabilidades, utilize o GitHub Security Advisories (quando disponível). Não divulgue payloads sensíveis ou credenciais em issues públicas.

Este projeto opera como honeypot SMTP: recebe dados para análise, mas não encaminha, entrega ou responde a remetentes com mensagens de e-mail. Não acessa links nem envia o conteúdo coletado para serviços externos. Escuta apenas em loopback por padrão; ativar --allow-public-bind requer autorização, ambiente isolado, firewall, contenção de saída e política de retenção.

O registro JSONL contém IP de origem, domínios, hashes e indicadores. IPs podem constituir dados pessoais. Proteja arquivos e backups, restrinja o acesso e aplique prazos adequados de retenção. O corpo das mensagens e URLs completas não são persistidos.

Os eventos não têm assinatura digital e não constituem trilha imutável. Um atacante com acesso à máquina ou à escrita no arquivo pode alterar os registros. Em produção, integre a solução a um SIEM/armazenamento com retenção imutável.

As heurísticas de URL não provam phishing e este software não substitui filtragem antispam ou um servidor de e-mail corporativo.
