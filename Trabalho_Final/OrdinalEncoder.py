
# Código para tranformar as columas com valor categorico com o OrginalEncoder
# Colunas: "access_authentication","access_complexity","access_vector","impact_availability","impact_confidentiality","impact_integrity"

from sklearn.preprocessing import OrdinalEncoder

enc = OrdinalEncoder()
#Carrega o CSV conteudo 80%
df_oe_80 = pd.read_csv("dataset/data-list-80.csv")
#Lista as colunas que possuem dados categoricos
list_collumns = ["access_authentication","access_complexity","access_vector","impact_availability","impact_confidentiality","impact_integrity"]
#Faz a tranformacao dos dados
datalist_oe_80[list_collumns] = enc.fit_transform(datalist_oe_80[list_collumns])
#Cria arquivo CSV com dados transformados
df_oe_80 = pd.DataFrame(datalist_oe_80)
df_oe_80.to_csv("dataset/data-list-80_OrdinalEncoder.csv", index=False, header=True, quoting=csv.QUOTE_ALL)
