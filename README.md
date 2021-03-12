Ciência de Dados para Segurança (CI1030) - Trabalho Final
=================
#### Alunos:

Michael A Hempkemeyer (PPGINF-202000131795)

Roger R R Duarte (PPGINF-202000131793)

<hr >

#### Objetivo do trabalho:

Em nosso trabalho um Dataset relacionado a CVEs foi utilizado. CVE (_Common Vulnerabilities and Exposures_) é um referência pública de segurança da informação relacionada a vulnerabilidades e exposições.

Verificando os campos do Dataset, o objetivo traçado foi o mapeamento de quais CVE geraram impacto e quais não geraram, isso com base nas variáveis do Dataset. Caber ressaltar que qualquer tipo de impacto, seja parcial ou completo, foi considerado como positivo em nosso experimento. 

Na sequência deste relatório, são apresentados o Dataset e seus respectivos rótulos, informações a respeito do pré-processamento do Dataset, gráficos distribuição de classes, informações de treinamentos, testes e resultados obtidos com o processamento do Dataset utilizando os algoritmos RandomForest, Kneighbors e SVM.

<hr >

#### Dataset: 

O dataset possui um arquivo único com diversos JSONs (um por linha) com informações específicas de CVEs (_Common Vulnerabilities and Exposures_). Acesso ao dataset completo em https://www.kaggle.com/vsathiamoo/cve-common-vulnerabilities-and-exposures/version/1.

Verificou-se que o dataset possuía os seguintes campos:

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
	
Os campos cvss, cwe, access, impact, summary e vulnerable_configuration_cpe_2_2 foram utilizados em nosso trabalho, sendo eliminados os demais através do pré-processamento, conforme [Exploração de Dados / ](https://github.com/rogerduarte/CienciaDeDados/tree/main/Explora%C3%A7%C3%A3o%20de%20Dados).


<hr >

#### Pré-processamento:

O pré-processamento foi realizado através do Script Python ["PreProcessamento.py"] (https://github.com/rogerduarte/CienciaDeDados/blob/main/Trabalho_Final/PreProcessamento.py)

Foi realizada a leitura do arquivo JSON de forma parcial e apenas as colunas cvss, cwe, access, impact, summary e vulnerable_configuration_cpe_2_2 foram mantidas.

As colunas summary e cvss foram utilizadas como base para determinar quais linhas do dataset seriam mantidas, visto que a coluna summary em determinados momentos possuía a mensagem "** REJECT ** DO NOT USE THIS CANDIDATE NUMBER" e a coluna cvss (score) possuia itens em branco. Dessa forma, o seguinte trecho de código foi utilizado para essas duas colunas:

```python
	elif d == "cvss":
		# Não inclui no dataset pre-processado itens com cvss zerados
		if tmp[d] is None:
		use_line = False
		break
	else:
		tmp_dict[d] = tmp[d]
```
								

```python
	elif d == "summary":
		# Em determinados casos, existe a marcação de "REJECT" no summary.
		# Tais CVEs que contêm o REJECT no summary serão eliminados
		# Ex.: ** REJECT **  DO NOT USE THIS CANDIDATE NUMBER.  ConsultIDs: none.  Reason: This ...
		if ("** REJECT **" in tmp[d].upper() or
			"DO NOT USE THIS CANDIDATE NUMBER" in tmp[d].upper()):
			use_line = False
			break
		tmp_dict[d] = tmp[d].replace("\"", "'")
```		

As colunas impact e access tiveram que passar por ajustes, visto que estas eram dicionários. Para a coluna summary, o seguinte trecho de código foi adicionado. Dessa forma, foi mapeado quais CVEs geraram impacto e quais não geraram (objetivo do trabalho).

```python
	elif d == "impact":
		if ((d in tmp.keys()) and
			(tmp[d]["availability"] == "PARTIAL" or tmp[d]["availability"] == "COMPLETE") and
			(tmp[d]["confidentiality"] == "PARTIAL" or tmp[d]["confidentiality"] == "COMPLETE") and
			(tmp[d]["integrity"] == "PARTIAL" or tmp[d]["integrity"] == "COMPLETE")):
			tmp_dict["impact"] = 1
		else:
			tmp_dict["impact"] = 0	
```	

Para a coluna access, o seguinte tratamento foi realizado:

```python
	self.control_access = {
		"vector": {
			"ADJACENT_NETWORK": 1,
			"LOCAL": 2,
			"NETWORK": 3
		},
		"complexity": {
			"HIGH": 5,
			"LOW": 6,
			"MEDIUM": 7
		},
		"authentication": {
			"MULTIPLE_INSTANCES": 9,
			"NONE": 10,
		"SINGLE_INSTANCE": 11
		},
		"NotAvailable": 12
	}
	
```

```python
	elif d == "access":
		if d in tmp.keys():
			# Faz a categorização do access conforme variável self.access_control
			tmp_dict["access"] = self.control_access["vector"][tmp[d]["vector"]]
			tmp_dict["access"] += self.control_access["authentication"][tmp[d]["authentication"]]
			tmp_dict["access"] += self.control_access["complexity"][tmp[d]["complexity"]]
		else:
			tmp_dict["access"] = self.control_access["NotAvailable"]						
```


Com o trecho acima, a coluna access que antes era um dicionário, foi mapeada para um valor número. Isto foi realizado para facilitar o mapeamento posterior da característica.

O campo vulnerable_configuration_cpe_2_2, que possui informações a respeito do ambiente que possui a vulnerabilidade do CVE, foi convertida de uma lista de strings para uma única string, conforme trecho de código abaixo:

```python
	elif d == "vulnerable_configuration_cpe_2_2":
		if type(tmp[d]) is list and len(tmp[d]) > 0:
			tmp_vc = ""
			for i in tmp[d]:
				tmp_vc = tmp_vc+";"+i
			tmp_dict[d] = tmp_vc
		else:
			tmp_dict[d] = "NotAvailable"
```

Como resultado final do script foram criados dois arquivos CVS pré-processados, um com uma porção de 80% dos dados e outra com 20%.

<hr >

#### Distribuição de classes

Conforme saída do CSV de pré-processamento, foram criados dois gráficos do mapa de distribuição de classes, com base no campo impact.

A seguir são apresentados os gráficos de distribuição de classe das porções de 20% e 80%.

![Gráfico Distribuição Classe 20%](./Trabalho_Final/Gráfico_Dist_Classes/grafico_dist_20.png)

![Gráfico Distribuição Classe 80%](./Trabalho_Final/Gráfico_Dist_Classes/grafico_dist_80.png)


<hr >
#### Treinamentos, testes e resultados 

Após o prévio processamento do dataset “circl-cve-search-expanded.json” – escolha das informações de interesse e divisão dos dados em dois grupos, um com 80% e o outro com 20% dos dados – foi realizado o treinamento do dataset com a porção de 80% das informações nos modelos RandomForest, Kneighborn e Support-vector machine (SVM). Para isso, além de outras bibliotecas, foram utilizadas a biblioteca de aprendizado de máquina scikit-learn e a biblioteca de criação de gráficos e visualizações de dados em geral Matplotlib, ambas para a linguagem de programação Python.
```python

import math
import sys
import time

import pandas as pd
import os

from gensim.models import Word2Vec
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import StratifiedKFold
from sklearn.preprocessing import MinMaxScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, precision_score, mean_absolute_error
import numpy as np
from sklearn.neighbors import KNeighborsClassifier
from sklearn.svm import SVC
import matplotlib.pyplot as plt
from sklearn.metrics import plot_roc_curve
```

O treinamento, teste e obtenção dos resultados foi realizado através do Script Python ["ImplementacaoModelos.py"]  (https://github.com/rogerduarte/CienciaDeDados/blob/main/Trabalho_Final/ImplementacaoModelos.py)


<hr >
#### 1) RandonForest

   a) treinamento/teste
   b) resultado split/resultado kfold/curva roc
   c) discussão resultados

#### 2) Kneighborn

   a) treinamento/test
   b) resultado split/resultado kfold/curva roc
   c) discussão resultados

#### 3) SVM

   a) treinamento/test
   b) resultado split/resultado kfold/curva roc
   c) discussão resultados

<hr >
20%
#### 1) RandonForest
   a) treinamento/teste
   b) resultado split/resultado kfold/curva roc
   c) discussão resultados

####  2) Kneighborn
   a) treinamento/test
   b) resultado split/resultado kfold/curva roc
   c) discussão resultados

#### 3) SVM
   a) treinamento/test
   b) resultado split/resultado kfold/curva roc
   c) discussão resultados


