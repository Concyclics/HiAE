# %%
import pandas as pd
import seaborn as sns

# %%
ds = pd.read_csv("speed.csv")
ds

# %%
ds_max = ds.groupby(["Cipher", "CPU", "Mode"]).max().reset_index()
ds_max

# %%
ds_max["CPU"].unique()

# %%
# 提取每个Cipher的最大Speed值，并生成排序后的列表
cipher_order = (
    ds_max[~ds_max["Cipher"].isin(["SNOW-V-GCM"]) & ds_max["Mode"].isin(["AEAD"]) & ds_max["CPU"].isin(["AMD Ryzen 9 7950X", "Intel Xeon W9-3495X", "HiSilicon Kunpeng 920X", "Apple M3 Pro"])]
    .groupby("Cipher")["Speed"]
    .max()
    .sort_values(ascending=False)
    .index.tolist()
)

# %%
import matplotlib.pyplot as plt
sns.set_theme("poster", style="whitegrid", palette="")
plt.figure(figsize=(16, 8))
sns.barplot(
    data=ds_max[~ds_max["Cipher"].isin(["SNOW-V-GCM"]) & ds_max["Mode"].isin(["AEAD"]) & ds_max["CPU"].isin(["AMD Ryzen 9 7950X", "Intel Xeon W9-3495X", "HiSilicon Kunpeng 920X", "Apple M3 Pro"])],
    x="Cipher", 
    y="Speed", 
    hue="CPU",
    order=cipher_order,  # 关键：按最大值排序后的顺序
    hue_order=["AMD Ryzen 9 7950X", "Apple M3 Pro", "Intel Xeon W9-3495X", "HiSilicon Kunpeng 920X"]
)
plt.title("AEAD Peak Throughput Cross Platforms")
plt.ylabel("Speed (Gbps)")
plt.xticks(rotation=30)
plt.xlabel("")
plt.savefig("Throughput.png", dpi=600, bbox_inches='tight', transparent=True)


