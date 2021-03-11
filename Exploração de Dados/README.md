Ciência de Dados para Segurança (CI1030) - Trabalho Final
=================

- **Que tipos de dados você tem, majoritariamente (atributos numéricos, textuais)?**

Majoritariamente os dados são textuais, por se tratarem de informações a respeito de vulnerabilidade conhecidas.

- **Qual seu objetivo com esse dataset?**

O objetivo é obter informações gerais de vulnerabilidades conhecidas, indicando quais CVEs geram impacto ou não em determinados ambientes conforme as configurações destes.

- **Seu dataset é rotulado de que maneira?**

Verificou-se que o dataset possui os seguintes campos:

    - Modified | tipo: date
    - Published | tipo: date
    - Access | tipo: dict { "authentication": 
                                "MULTIPLE_INSTANCES", "NONE" ou "SINGLE_INSTANCE",
                            "complexity":
                                "HIGH", "LOW" ou "MEDIUM", 
                            "vector":
                                "ADJACENT_NETWORK", "LOCAL" ou "NETWORK"
							}
    - Capec | tipo: list() | obs.: Common Attack Pattern Enumeration and Classification (CAPEC™)
    - Cvss | tipo: float
    - Cvss-time | tipo: date
    - Cwe | tipo: string
    - id (Cve-id) | tipo: string
    - Impact | tipo: dict  { "availability":
                                 "PARTIAL", "COMPLETE" ou "NONE", 
                             "confidentiality":
                                 "PARTIAL", "COMPLETE" ou "NONE", 
                             "integrity":
                                 "PARTIAL", "COMPLETE" OU "NONE"
							}
    - last-modified | tipo: date
    - Nessus | tipo: list() | obs.: Informação fornecida pelo www.tenable.com, indica CVEs relacionados
    - References | tipo: list()
    - Summary | tipo: string
    - Vulnerable_configuration | tipo: list() | obs.: configuração do produto vulnerável
    - Vulnerable_configuration_cpe_2_2 | tipo: list() | obs.: configuração do produto vulnerável

A rotulação foi feita de forma manual, conforme apresentado no JSON do dataset.

- **Como é a distribuição dos dados do dataset?**

O dataset é um arquivo único em formato JSON com informações dos CVEs. Cada linha do arquivo contém um JSON com informações de um CVE específico, contendo os atributos mencionados no questionário acima

Recomenda-se baixar o dataset completo (JSON) direto do endereço: https://www.kaggle.com/vsathiamoo/cve-common-vulnerabilities-and-exposures/version/1.

O arquivo "Exploração_Dados.py" é um exemplo de arquivo para a exploração de dados do dataset. Cabe ressaltar que o dataset foi pré-processado pelo script "Trabalho_Final / PreProcessamento.py" antes de ser realizada a exploração dos dados.

As tabelas a seguir foram geradas com a pré-análise do dataset. 

| Variável | Número de registros |
| --- | --- |
| cvss | 99885 |
| cwe | 99885 |
| access  | 99885 |
| impact | 99885 |
| cvss-time | 99885 |
| summary  | 99885 |
| vulnerable_configuration_cpe_2_2 | 99885 |

- A tabela acima indica que o número total de CVEs pré-processados do dataset é 99885.

| Scores (cvss) | Número de registros |
| --- | --- |
| 7.5 | 16273 |
| 4.3 | 14798 |
| 5.0 | 14525 |
| 6.8 | 7773 |
| 10.0 | 6927 |

- A tabela acima faz um groupby pelo atributo csvss e mostra os cinco scores mais comuns

| Categoria | Número de registros |
| --- | --- |
| CVEs que não geraram impacto | 55615 | 
| CVEs que geraram impacto | 44270 | 

- A tabela acima faz um groupby pelos atributos impact e mostra a distribuição dos CVEs que geraram ou não impacto. Ressalta-se que para saber de um determinado CVE gerou impacto, foi verificado se os campos availability, confidentiality e integrity eram PARTIAL ou COMPLETE.


- **Quais colunas/atributos você julga ser interessante manter e remover? Por quê?**

Atributos que serão mantidos: 

    - cvss
    - cwe, 
    - access, 
    - impact, 
    - summary, 
    - vulnerable_configuration_cpe_2_2,

O objetivo do trabalho é indicar se um determinado CVE, com base no cvss (score), cwe, access, summary e vulnerable_configuration_cpe_2_2, gera impacto (1) ou não (0)

Desta forma, os seguintes atributos foram removidos:

    - id -> não é de interesse do trabalho saber apenas o ID do CVE
	- Modified/Published/Cvss-time/Last-modified -> não é de interesse do trabalho saber informações a respeito de data
    - Capec -> não é de interesse do trabalho saber o CAPEC, visto que não será útil para atingir os objetivos já mencionados.
    - Nessus -> não é de interesse do trabalho saber CVEs possivelmente relacionados, visto que não será útil para atingir os objetivos já mencionados.
    - References -> não é de interesse do trabalho saber a referência do CVE.
    - Vulnerable_configuration -> a informação já é obtida pela variável Vulnerable_configuration_cpe_2_2.

