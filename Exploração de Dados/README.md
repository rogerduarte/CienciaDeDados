Ciência de Dados para Segurança (CI1030) - Trabalho Final
=================

- **Que tipos de dados você tem, majoritariamente (atributos numéricos, textuais)?**

Majoritariamente os dados são textuais, por se tratarem de informações a respeito de vulnerabilidade conhecidas.

- **Qual seu objetivo com esse dataset?**

O ojetivo é obter informações gerais de vulnerabilidade conhecidas, com detalhes específicos sobre quais produtos possuem mais vulnerabilidade conhecidas, quais tipos de configurações, scores, 
formas de acesso e impactos divulgados pelos CVEs.  

- **Seu dataset é rotulado de que maneira?**

Verificou-se que o dataset possui os seguintes campos:

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

- **Como é a distribuição dos dados do dataset?**

O dataset é um arquivo único em formato JSON com informações dos CVEs. Cada linha do arquivo contém um JSON com informações de um CVE específico, contendo os atributos mencionados no questionário acima

Cabe mencionar que, conforme o CVE, alguns dos campos supramencionados podem ser suprimidos (são preenchidos com None na análise preliminar)

O diretório "Exemplos JSON", possui três arquivos JSON extraídos do dataset.

Recomenda-se baixar o dataset completo direto do endereço: https://www.kaggle.com/vsathiamoo/cve-common-vulnerabilities-and-exposures/version/1.

O arquivo "Exploração_Dados.py" possui um pequeno de exemplo de leitura do dataset, tratamento das variáveis e também exploração de dados.

As tabelas a seguir foram geradas com a pré-análise do dataset. 

| Váriavel | Número de registros |
| --- | --- |
| Modified | 106856 |
| Published | 106856 |
| access | 84981 |
| cvss | 99885 |
| cvss-time | 84981 |
| impact | 84981 |
| references | 106856 |
| summary |  106856 |
| vulnerable_configuration_cpe_2_2 | 106856
| id | 106856 |

- A tabela acima indica que o número total de CVEs do dataset é 106856, e que existem alguns atributos que estão suprimidos no dataset (Ex.: o atributo "access" foi encontrado em 84981 CVEs, "id" foi encontrado em todos os CVEs, etc). Isso será levado em conta na análise posterior.

| Scores (cvss) | Número de registros |
| --- | --- |
| 7.5 | 16273 |
| 4.3 | 14798 |
| 5.0 | 14525 |
| 6.8 | 7773 |

| Ano (cvss) | Número de registros |
| --- | --- |
| 2017-12-31 | 18114 |
| 2014-12-31 | 8017 |
| 2018-12-31 | 7898 |
| 2006-12-31 | 6659 |
| 2007-12-31 | 6596 |
| 2015-12-31 | 6588 |
| 2016-12-31 | 6515 |
| 2009-12-31 | 5778 |
| 2008-12-31 | 5664 |
| 2012-12-31 | 5351 |


- **Quais colunas/atributos você julga ser interessante manter e remover? Por quê?**

Atributos que serão mantidos: 

    - Modified
    - Published, 
    - Access, 
    - Cvss, 
    - Cvss-time, 
    - Impact, 
	- id,
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
