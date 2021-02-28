Ciência de Dados para Segurança (CI1030) - Trabalho Final
=================

- **Que tipos de dados você tem, majoritariamente (atributos numéricos, textuais)?**

Majoritariamente os dados são textuais, por se tratarem de informações a respeito de vulnerabilidade conhecidas.

- **Qual seu objetivo com esse dataset?**

O ojetivo é obter informações gerais de vulnerabilidade conhecidas, com detalhes específicos sobre quais produtos possuem mais vulnerabilidade conhecidas, quais tipos de configurações, scores, 
formas de acesso e impactos divulgados pelos CVEs.  

- **Seu dataset é rotulado de que maneira?**

VERIFICAR

- **Como é a distribuição dos dados do dataset?**

O dataset é um arquivo único JSON com informações dos CVEs.
Para cada linha do arquivo, são incluídas informações de um CVE contendo os atributos:

    - Modified (data)
    - Published (data)
    - Access (tipo de acesso) {authentication, complexity, vector}
    - Capec (Common Attack Pattern Enumeration and Classification (CAPEC™))
    - Cvss (score, float)
    - Cvss-time (data)
    - Cwe (texto)
    - id (Cve-id) (texto)
    - Impact (impacto) {availability, confidentiality, integrity)
    - last-modified (última modificação)
    - Nessus [] (Informação fornecida pelo www.tenable.com, possivelmente indica CVEs relacionados)
    - References (sites com referências)
    - Summary (descrição do CVE)
    - Vulnerable_configuration (configuração do produto vulnerável)
    - Vulnerable_configuration_cpe_2_2 (configuração do produto vulnerável)

Cabe mencionar que, conforme o CVE, alguns dos campos supramencionados podem ser suprimidos.

O diretório "Exemplos JSON", possui três arquivos JSON extraídos da base principal para exemplos.

Recomenda-se baixar o dataset completo direto do endereço: https://www.kaggle.com/vsathiamoo/cve-common-vulnerabilities-and-exposures/version/1.

- **Quais colunas/atributos você julga ser interessante manter e remover? Por quê?**

Atributos que serão mantidos: 

    - Modified
    - Published, 
    - Access, 
    - Cvss, 
    - Cvss-time, 
    - Impact, 
    - References, 
    - Summary
    - Vulnerable_configuration_cpe_2_2

A ideia é que possamos obter informações gerais do CVE, com informações dos produtos vulneráveis, quais tipos de configurações, scores, 
formas de acesso e impactos divulgados pelos CVEs. Essas informações podem ser obtidas através dos atributos acima.

Atributos removidos:

    - Capec -> não é de interesse do trabalho saber o CAPEC, visto que não será útil para atingir os objetivos já mencionados.
    - Last-modified -> essa informação já obtida pelos outros campos
    - Nessus -> não é de interesse do trabalho saber CVEs possivelmente relacionados, visto que não será útil para atingir os objetivos já mencionados.
    - Vulnerable_configuration -> a informação será obtida pela variável Vulnerable_configuration_cpe_2_2


- **Escreva um relatório no repositório GitHub do seu projeto**

VERIFICAR