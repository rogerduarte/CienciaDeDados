from Trabalho_Final.PreProcessamento import PreProcessDataSet
import os.path

# Criação da classe de pré-processamento
pre_process = None
# Pasta para o armazenamentos dos arquivos PDF com os gráficos
folder_graphics = "graficos"
# Variável de control
count = 1


def generate_graphics_80():
    """
    Gera os gráficos em formato PDF para a distribuição de 80%
    :return:
    """
    global count, pre_process, folder_graphics

    # Criação gráfico PUBLICAÇÃO DE CVE POR ANO  (80%)
    tmp = pre_process.df_80.fillna('N/A').groupby([pre_process.df_80['Published'].dt.year]).size()
    ax = tmp.plot(kind="bar", figsize=(6, 6))
    ax.set_xlabel("Ano")
    ax.set_ylabel("Nº de CVEs")
    ax.figure.suptitle('PUBLICAÇÃO DE CVEs POR ANO (porção 80%)')
    ax.figure.savefig(os.path.join(folder_graphics, str(count)+'-80-cve-por-ano.pdf'))

    # IMPACTO (impact_availability) POR ANO DE PUBLICAÇÃO (80%)
    count += 1
    tmp = pre_process.df_80.fillna('N/A').groupby([pre_process.df_80['Published'].dt.year, 'impact_availability']).size()
    ax = tmp.plot(kind="bar", figsize=(25, 15))
    ax.set_xlabel("Ano e categoria de impacto")
    ax.set_ylabel("Nº de CVEs")
    ax.figure.suptitle('IMPACTO (impact_availability) POR ANO DE PUBLICAÇÃO (porção 80%)')
    ax.figure.savefig(os.path.join(folder_graphics, str(count)+'-80-impact_availability-por-ano.pdf'))

    # IMPACTO (impact_confidentiality) POR ANO DE PUBLICAÇÃO (80%)")
    count += 1
    tmp = pre_process.df_80.fillna('N/A').groupby([pre_process.df_80['Published'].dt.year, 'impact_confidentiality']).size()
    ax = tmp.plot(kind="bar", figsize=(25, 15))
    ax.set_xlabel("Ano e categoria de impacto")
    ax.set_ylabel("Nº de CVEs")
    ax.figure.suptitle('IMPACTO (impact_confidentiality) POR ANO DE PUBLICAÇÃO (porção 80%)')
    ax.figure.savefig(os.path.join(folder_graphics, str(count)+'-80-impact_confidentiality-por-ano.pdf'))

    # IMPACTO (impact_integrity) POR ANO DE PUBLICAÇÃO (80%)")
    count += 1
    tmp = pre_process.df_80.fillna('N/A').groupby([pre_process.df_80['Published'].dt.year, 'impact_integrity']).size()
    ax = tmp.plot(kind="bar", figsize=(25, 15))
    ax.set_xlabel("Ano e categoria de impacto")
    ax.set_ylabel("Nº de CVEs")
    ax.figure.suptitle('IMPACTO (impact_integrity) POR ANO DE PUBLICAÇÃO (porção 80%)')
    ax.figure.savefig(os.path.join(folder_graphics, str(count)+'-80-impact_integrity-por-ano.pdf'))

    # ACESSO (access_authentication) POR ANO DE PUBLICAÇÃO (80%)"
    count += 1
    tmp = pre_process.df_80.fillna('N/A').groupby([pre_process.df_80['Published'].dt.year, 'access_authentication']).size()
    ax = tmp.plot(kind="bar", figsize=(25, 15))
    ax.set_xlabel("Ano e categoria de acesso")
    ax.set_ylabel("Nº de CVEs")
    ax.figure.suptitle('Acesso (access_authentication) POR ANO DE PUBLICAÇÃO (porção 80%)')
    ax.figure.savefig(os.path.join(folder_graphics, str(count)+'-80-access_authentication-por-ano.pdf'))

    # ACESSO (access_complexity) POR ANO DE PUBLICAÇÃO (80%)"
    count += 1
    tmp = pre_process.df_80.fillna('N/A').groupby([pre_process.df_80['Published'].dt.year, 'access_complexity']).size()
    ax = tmp.plot(kind="bar", figsize=(25, 15))
    ax.set_xlabel("Ano e categoria de acesso")
    ax.set_ylabel("Nº de CVEs")
    ax.figure.suptitle('Acesso (access_complexity) POR ANO DE PUBLICAÇÃO (porção 80%)')
    ax.figure.savefig(os.path.join(folder_graphics, str(count)+'-80-access_complexity-por-ano.pdf'))

    # ACESSO (access_vector) POR ANO DE PUBLICAÇÃO (80%)"
    count += 1
    tmp = pre_process.df_80.fillna('N/A').groupby([pre_process.df_80['Published'].dt.year, 'access_vector']).size()
    ax = tmp.plot(kind="bar", figsize=(25, 15))
    ax.set_xlabel("Ano e categoria de acesso")
    ax.set_ylabel("Nº de CVEs")
    ax.figure.suptitle('Acesso (access_vector) POR ANO DE PUBLICAÇÃO (porção 80%)')
    ax.figure.savefig(os.path.join(folder_graphics, str(count)+'-80-access_vector-por-ano.pdf'))


def generate_graphics_20():
    """
    Gera os gráficos em formato PDF para a distribuição de 20%
    :return:
    """
    global count, pre_process, folder_graphics

    count += 1
    # Criação gráfico PUBLICAÇÃO DE CVE POR ANO  (20%)
    tmp = pre_process.df_20.fillna('N/A').groupby([pre_process.df_20['Published'].dt.year]).size()
    ax = tmp.plot(kind="bar", figsize=(6, 6))
    ax.set_xlabel("Ano")
    ax.set_ylabel("Nº de CVEs")
    ax.figure.suptitle('PUBLICAÇÃO DE CVEs POR ANO (porção 20%)')
    ax.figure.savefig(os.path.join(folder_graphics, str(count)+'-20-cve-por-ano.pdf'))

    # IMPACTO (impact_availability) POR ANO DE PUBLICAÇÃO (20%)
    count += 1
    tmp = pre_process.df_20.fillna('N/A').groupby([pre_process.df_20['Published'].dt.year, 'impact_availability']).size()
    ax = tmp.plot(kind="bar", figsize=(25, 15))
    ax.set_xlabel("Ano e categoria de impacto")
    ax.set_ylabel("Nº de CVEs")
    ax.figure.suptitle('IMPACTO (impact_availability) POR ANO DE PUBLICAÇÃO (porção 20%)')
    ax.figure.savefig(os.path.join(folder_graphics, str(count)+'-20-impact_availability-por-ano.pdf'))

    # IMPACTO (impact_confidentiality) POR ANO DE PUBLICAÇÃO (20%)")
    count += 1
    tmp = pre_process.df_20.fillna('N/A').groupby([pre_process.df_20['Published'].dt.year, 'impact_confidentiality']).size()
    ax = tmp.plot(kind="bar", figsize=(25, 15))
    ax.set_xlabel("Ano e categoria de impacto")
    ax.set_ylabel("Nº de CVEs")
    ax.figure.suptitle('IMPACTO (impact_confidentiality) POR ANO DE PUBLICAÇÃO (porção 20%)')
    ax.figure.savefig(os.path.join(folder_graphics, str(count)+'-20-impact_confidentiality-por-ano.pdf'))

    # IMPACTO (impact_integrity) POR ANO DE PUBLICAÇÃO (20%)")
    count += 1
    tmp = pre_process.df_20.fillna('N/A').groupby([pre_process.df_20['Published'].dt.year, 'impact_integrity']).size()
    ax = tmp.plot(kind="bar", figsize=(25, 15))
    ax.set_xlabel("Ano e categoria de impacto")
    ax.set_ylabel("Nº de CVEs")
    ax.figure.suptitle('IMPACTO (impact_integrity) POR ANO DE PUBLICAÇÃO (porção 20%)')
    ax.figure.savefig(os.path.join(folder_graphics, str(count)+'-20-impact_integrity-por-ano.pdf'))

    # ACESSO (access_authentication) POR ANO DE PUBLICAÇÃO (20%)"
    count += 1
    tmp = pre_process.df_20.fillna('N/A').groupby([pre_process.df_20['Published'].dt.year, 'access_authentication']).size()
    ax = tmp.plot(kind="bar", figsize=(25, 15))
    ax.set_xlabel("Ano e categoria de acesso")
    ax.set_ylabel("Nº de CVEs")
    ax.figure.suptitle('ACESSO (access_authentication) POR ANO DE PUBLICAÇÃO (porção 20%)')
    ax.figure.savefig(os.path.join(folder_graphics, str(count)+'-20-access_authentication-por-ano.pdf'))

    # ACESSO (access_complexity) POR ANO DE PUBLICAÇÃO (20%)"
    count += 1
    tmp = pre_process.df_20.fillna('N/A').groupby([pre_process.df_20['Published'].dt.year, 'access_complexity']).size()
    ax = tmp.plot(kind="bar", figsize=(25, 15))
    ax.set_xlabel("Ano e categoria de acesso")
    ax.set_ylabel("Nº de CVEs")
    ax.figure.suptitle('ACESSO (access_complexity) POR ANO DE PUBLICAÇÃO (porção 20%)')
    ax.figure.savefig(os.path.join(folder_graphics, str(count)+'-20-access_complexity-por-ano.pdf'))

    # ACESSO (access_vector) POR ANO DE PUBLICAÇÃO (20%)"
    count += 1
    tmp = pre_process.df_20.fillna('N/A').groupby([pre_process.df_20['Published'].dt.year, 'access_vector']).size()
    ax = tmp.plot(kind="bar", figsize=(25, 15))
    ax.set_xlabel("Ano e categoria de acesso")
    ax.set_ylabel("Nº de CVEs")
    ax.figure.suptitle('ACESSO (access_vector) POR ANO DE PUBLICAÇÃO (porção 20%)')
    ax.figure.savefig(os.path.join(folder_graphics, str(count)+'-20-access_vector-por-ano.pdf'))


if __name__ == "__main__":
    print(f"Criação da pasta de destino dos gráfico \"{folder_graphics}\" ...")
    if os.path.isdir(folder_graphics) is False:
        os.mkdir(folder_graphics)
    print("Leitura e pré-processamento do dataset ...")
    pre_process = PreProcessDataSet()
    pre_process.read_dataset_to_list()
    print("Particionamento dos dados do dataset em 80% e 20% ...")
    pre_process.partition_80_20()
    print("Gerando gráficos da porção de 80% ...")
    generate_graphics_80()
    print("Gerando gráficos da porção de 20% ...")
    generate_graphics_20()
    print("Finalizado!")
