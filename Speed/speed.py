# %%
import pandas as pd

# %%
ds = pd.read_csv("speed.csv")
ds = ds.sort_values(by=['CPU', 'Cipher', 'Mode', "Length"])
#ds.to_csv("speed.csv")
ds

# %%
for speed in ds["Speed"].unique():
    lens = len(ds[(ds["Speed"] == speed)])
    if lens > 1:
        print(ds[(ds["Speed"] == speed)])

# %%
for CPU in ds["CPU"].unique():
    for Mode in ds["Mode"].unique():
        for Cipher in ds["Cipher"].unique():
                #lens = len(ds[(ds["Cipher"] == Cipher)&(ds["CPU"] == CPU) & (ds["Mode"] == Mode)])
                #if lens == 7 or lens == 0:
                #     continue
                #print(Cipher, CPU, Mode, lens)
                print(ds[(ds["Cipher"] == Cipher)&(ds["CPU"] == CPU) & (ds["Mode"] == Mode)])

# %%


# %%
ds["CPU-Mode"] = ds["CPU"] + " - " + ds["Mode"]
ds

# %%
ds[ds["CPU"] == "AMD Ryzen 9 7950X"]

# %%
import pandas as pd
import plotly.graph_objects as go

df = ds

cpu_modes = df['CPU-Mode'].unique()
ciphers = df['Cipher'].unique()

# 初始化图表
fig = go.Figure()

# 为每个 Cipher 和 CPU-Mode 组合添加一个 Trace
for cipher in ciphers:
    for mode in cpu_modes:
        df_subset = df[(df['Cipher'] == cipher) & (df['CPU-Mode'] == mode)]
        print(cipher, mode, len(df_subset))
        fig.add_trace(
        go.Scatter(
                x=df_subset['Length'],
                y=df_subset['Speed'],
                mode='lines+markers',  # 使用折线和标记
                name=cipher,
                line=dict(width=2),
                marker=dict(size=8),
                visible=(mode == cpu_modes[0]),  # 初始时仅显示第一个 CPU-Mode
                legendgroup=cipher
            )
        )

# 创建下拉菜单按钮
buttons = []
for mode in cpu_modes:
    # 定义每个 Trace 的可见性
    visibility = []
    for cipher in ciphers:
        for m in cpu_modes:    
            visibility.append(m == mode)
    
    buttons.append(
        dict(
            label=mode,
            method='update',
            args=[
                {'visible': visibility},
                {'title': f'CPU Mode: {mode}'}  # 更新图表标题
            ]
        )
    )

# 选择下拉菜单的位置
# 示例 1: 顶部中心
dropdown_top_center = dict(
    active=0,
    buttons=buttons,
    x=1.0,  # 水平居中
    y=1.15,  # 略高于图表顶部
    xanchor='right',
    yanchor='top'
)

# 示例 2: 底部右侧
dropdown_bottom_right = dict(
    active=0,
    buttons=buttons,
    x=1.0,  # 右侧
    y=-0.15,  # 略低于图表底部
    xanchor='right',
    yanchor='top'
)

# 选择您想要的位置，取消注释相应的行
selected_dropdown = dropdown_top_center  # 更改为 dropdown_bottom_right 以移动到底部右侧

# 添加下拉菜单到布局
fig.update_layout(
    updatemenus=[
        selected_dropdown
    ],
    title=f'CPU Mode: {cpu_modes[0]}',
    xaxis_title='Length',
    yaxis_title='Speed',
    legend_title='Cipher',
    template='plotly_white',
    width=1200,
    height=600
)

# 显示图表
fig.write_html("speed.html")


