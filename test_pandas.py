import pandas as pd

df_cve = pd.read_csv('dataset/cve.csv')
df_products = pd.read_csv('dataset/products.csv')
df_vendor_product = pd.read_csv('dataset/vendor_product.csv')
df_vendor = pd.read_csv("dataset/vendors.csv")

print(f'dataset/cve.csv: {df_cve.columns}')
print(df_products.columns)
print(df_vendor_product.columns)
print(df_vendor.columns)

df_m = pd.merge(df_cve, df_products, on="cve_id")
