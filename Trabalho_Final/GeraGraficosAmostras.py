"""
Trabalho final - Ciência de Dados para Segurança (CI1030) - Trabalho Final
Alunos:
    Michael A Hempkemeyer (PPGINF-202000131795)
    Roger R R Duarte (PPGINF-202000131793)

Antes de executar esse script, execute o pré-processamento através do py "PreProcessamento.py"
Esse script faz a geração do gráfico de distribuição por classes do dataset
"""
import sys
import os.path
import pandas as pd
import matplotlib.pyplot as plt

# Caminho dos DataSets
data_path_80 = os.path.join("dataset", "data-list-80.csv")
data_path_20 = os.path.join("dataset", "data-list-20.csv")

# Verifica se os arquivos de dataset pré-processados existem
if os.path.isfile(data_path_80) is False or os.path.isfile(data_path_20) is False:
    print(f"Arquivos \"{data_path_80}\" e \"{data_path_20}\" não encontrados")
    print("Execute primeiramente o pré-processamento com o script \"PreProcessamento.py\"")
    sys.exit(-1)

# Atribuição das colunas conforme o tipo das colunas
all_attributes = ["cvss", "cwe", "access", "impact", "summary", "vulnerable_configuration_cpe_2_2"]
textual_attributes = ["cwe", "summary", "vulnerable_configuration_cpe_2_2"]
numerical_attributes = ["cvss", "access"]
label_attribute = "impact"

print(f"Leitura dos datasets \"{data_path_80}\" e \"{data_path_20}\" ...")
df_80 = pd.read_csv(data_path_80)
df_20 = pd.read_csv(data_path_20)

# Pasta para o armazenamentos dos arquivos PDF com os gráficos
folder_graphics = "Gráfico_Dist_Classes"
print(f"Criação da pasta de destino dos gráfico \"{folder_graphics}\" ...")
if os.path.isdir(folder_graphics) is False:
    os.mkdir(folder_graphics)

print("Gerando gráficos ... ")

fig = plt.figure()

ax_80 = fig.add_subplot(211)
ax_80 = df_80[label_attribute].groupby(df_80[label_attribute]).count().plot(kind="bar")
ax_80.set_xlabel("Impacto")
ax_80.set_ylabel("Quantidade")
ax_80.set_xticklabels(["CVEs que não geraram impacto", "CVEs que geraram impacto"], rotation='horizontal')
ax_80.set_title("Distribuição de Classes (Impacto CVEs) - Distribuição 80%")
fig.tight_layout()

ax_20 = fig.add_subplot(212)
ax_20 = df_20[label_attribute].groupby(df_20[label_attribute]).count().plot(kind="bar")
ax_20.set_xlabel("Impacto")
ax_20.set_ylabel("Quantidade")
ax_20.set_xticklabels(["CVEs que não geraram impacto", "CVEs que geraram impacto"], rotation='horizontal')
ax_20.set_title("Distribuição de Classes (Impacto CVEs) - Distribuição 20%")
fig.tight_layout()

plt.savefig(os.path.join(folder_graphics, "distribuição-de-classes.pdf"))

print(f"Finalizado. Arquivo PDF com os gráficos salvo em \"{folder_graphics}\"")
