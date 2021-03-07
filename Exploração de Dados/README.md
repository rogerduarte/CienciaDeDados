Ciência de Dados para Segurança (CI1030) - Trabalho Final
=================

- **Que tipos de dados você tem, majoritariamente (atributos numéricos, textuais)?**

Majoritariamente os dados são textuais, por se tratarem de informações a respeito de vulnerabilidade conhecidas.
Foram constatados também atributos numéricos e com datas.

- **Qual seu objetivo com esse dataset?**

O objetivo é obter informações gerais de vulnerabilidade conhecidas, com detalhes específicos sobre quais produtos possuem mais vulnerabilidade conhecidas, quais tipos de configurações, scores, 
formas de acesso e impactos divulgados pelos CVEs.  

- **Seu dataset é rotulado de que maneira?**

Verificou-se que o dataset possui os seguintes campos:

    - Modified (date)
    - Published (date)
    - Access dict{authentication, complexity, vector} (forma de acesso)
    - Capec list() (Common Attack Pattern Enumeration and Classification (CAPEC™))
    - Cvss (score, float)
    - Cvss-time (date)
    - Cwe (str)
    - id (Cve-id) (str)
    - Impact dict{availability, confidentiality, integrity)
    - last-modified (date)
    - Nessus [] list() (Informação fornecida pelo www.tenable.com, possivelmente indica CVEs relacionados)
    - References list() (sites com referências)
    - Summary str() (descrição do CVE)
    - Vulnerable_configuration list() (configuração do produto vulnerável)
    - Vulnerable_configuration_cpe_2_2 list() (configuração do produto vulnerável)

A rotulação foi feita de forma manual, conforme apresentado no JSON do dataset.

- **Como é a distribuição dos dados do dataset?**

O dataset é um arquivo único em formato JSON com informações dos CVEs. Cada linha do arquivo contém um JSON com informações de um CVE específico, contendo os atributos mencionados no questionário acima

Cabe mencionar que, conforme o CVE, alguns dos campos supramencionados podem ser suprimidos (são preenchidos com None na análise preliminar). O diretório "Exemplos JSON", possui três arquivos JSON extraídos do dataset.

Recomenda-se baixar o dataset completo direto do endereço: https://www.kaggle.com/vsathiamoo/cve-common-vulnerabilities-and-exposures/version/1.

O arquivo "Exploração_Dados.py" é um exemplo de leitura do dataset, tratamento das variáveis e também exploração de dados.

As tabelas a seguir foram geradas com a pré-análise do dataset. 

| Variável | Número de registros |
| --- | --- |
| Modified | 101062 |
| Published | 101062 |
| access (authentication,complexity,vector)  | 84979 |
| cvss | 99885 |
| cvss-time | 84979 |
| impact (availability,confidentiality,integrity)  | 84979 |
| references | 100274 |
| summary |  101062 |
| vulnerable_configuration_cpe_2_2 | 99156
| id | 101062 |

- A tabela acima indica que o número total de CVEs do dataset é 101062, e que existem alguns atributos que estão suprimidos no dataset (Ex.: o atributo "access" foi encontrado em 84979 CVEs, "id" foi encontrado em todos os CVEs, etc). Isso será levado em conta na análise posterior.

| Scores (cvss) | Número de registros |
| --- | --- |
| 7.5 | 16273 |
| 4.3 | 14798 |
| 5.0 | 14525 |
| 6.8 | 7773 |

- A tabela acima faz um groupby pelo atributo csvss e mostra os quatro scores mais comuns

| Ano | Número de registros |
| --- | --- |
| 2017 | 14651 |
| 2014 | 7938 |
| 2006 | 6610 |
| 2007 | 6520 |
| 2015 | 6488 |

- A tabela acima faz um groupby pelo atributo Published e mostra os cinco anos que mais tiveram CVE publicados

| Categoria | Impacto (availability) | Impacto (confidentiality) | Impacto (integrity) |
| --- | --- | --- | --- |
| PARTIAL | 36370 | 39337 | 43865 |
| NONE | 27186 | 27056 | 23168 |
| COMPLETE | 21423 | 18586 | 17946 |
| Vazio | 16083 | 16083 | 16083 |

- A tabela acima faz um groupby pelos atributos availability, confidentiality e integrity (referentes ao dicionário impact) e 
mostra a distribuição de impactos dos CVEs


- **Quais colunas/atributos você julga ser interessante manter e remover? Por quê?**

Atributos que serão mantidos: 

    - Modified
    - Published, 
    - Access, 
    - Cvss, 
    - Cvss-time, 
    - Impact, 
	- id,

A ideia é que possamos obter informações gerais do CVE, com informações dos produtos vulneráveis, quais tipos de configurações, scores, 
formas de acesso e impactos divulgados pelos CVEs. Essas informações podem ser obtidas através dos atributos acima.

Atributos removidos:

    - Capec -> não é de interesse do trabalho saber o CAPEC, visto que não será útil para atingir os objetivos já mencionados.
    - Last-modified -> essa informação já obtida pelos outros campos
    - Nessus -> não é de interesse do trabalho saber CVEs possivelmente relacionados, visto que não será útil para atingir os objetivos já mencionados.
    - References -> não é de interesse do trabalho saber a referência do CVE.
    - Summary -> não é do interesse do trabalho saber um resumo da vulnerabilidade
    - Vulnerable_configuration -> não é de interesse do trabalho.
    - Vulnerable_configuration_cpe_2_2 -> não é de interesse do trabalho.


