#!/usr/bin/env python3
"""Render the adjacent measured HY2 benchmark JSON with matplotlib."""
import json
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.font_manager as fm
import matplotlib.pyplot as plt
import numpy as np

STEM = Path(__file__).with_suffix('')
data = json.loads(STEM.with_suffix('.json').read_text())
font = next((f.name for f in fm.fontManager.ttflist if f.name in
             ('Noto Sans CJK SC', 'Noto Sans CJK JP', 'Source Han Sans SC')), 'DejaVu Sans')
plt.rcParams.update({'font.family':font, 'font.size':11, 'axes.titlesize':14,
    'axes.titleweight':'bold', 'axes.labelcolor':'#30435a', 'text.color':'#162c43',
    'xtick.color':'#4c6075', 'ytick.color':'#4c6075', 'axes.spines.top':False,
    'axes.spines.right':False, 'axes.spines.left':False, 'axes.edgecolor':'#d8e0e7',
    'svg.fonttype':'none'})
green, purple, red, gray = '#218875', '#80619b', '#ce5b65', '#dbe1e8'
fig, axes = plt.subplots(2,2,figsize=(17,10.7))
fig.subplots_adjust(left=.16,right=.965,top=.845,bottom=.14,hspace=.45,wspace=.48)
fig.suptitle('撤回 HY2 自定义 RTT 保护和额外恢复上限',fontsize=22,fontweight='bold',y=.965)
fig.text(.5,.913,'本机隔离网络  ·  双向线路 1 Gbps  ·  原代理配置  ·  统计目标实际接收数据',
         ha='center',fontsize=12,color='#546c82')

speed = {x['case']:x['received_Mbps'] for x in data['final_speed']}
both = [speed['verify-both-up'],speed['verify-both-up-repeat']]
values = [speed['verify-control'],speed['verify-client-only'],speed['verify-server-only'],np.mean(both)]
labels = ['对照：保留旧服务端','仅清理客户端恢复上限','仅清理服务端','两端清理（两轮）']
ax = axes[0,0]
ax.set_title('A  单流 TCP 上传恢复到约 930 Mbps',loc='left',pad=15)
ax.barh(np.arange(4),values,color=[purple,'#a1abc0',green,green],height=.55,zorder=3)
ax.set_yticks(np.arange(4),labels)
ax.invert_yaxis(); ax.set_xlim(0,1060)
ax.set_xlabel('目标接收速率（Mbps）')
ax.set_xticks([0,200,400,600,800,1000]);ax.grid(axis='x',alpha=.2,zorder=0)
reference = data['earlier_same_topology_raw_TCP_reference_Mbps']
ax.axvline(reference,color='#6f8192',ls='--',lw=1,zorder=2)
ax.text(reference-8,-.61,f'先前直连校准 {reference:.1f}',ha='right',fontsize=10,color='#687b8b')
for i,v in enumerate(values):
    ax.text(v+14,i,f'{v:.1f}',va='center',fontsize=11,fontweight='bold')

cases = data['final_latency']
ax = axes[0,1]
ax.set_title('B  每组 400 个计划请求：完整覆盖情况',loc='left',pad=15)
names = ['抖动 · 旧服务端','抖动 · 修复两端','尖峰 · 旧服务端','尖峰 · 修复两端']
ys = np.arange(4)
left = np.zeros(4)
for key,label,color in [('successful_requests','成功',green),('request_errors','超时',red),
                        ('not_dispatched_busy_ticks','连接忙，未发出',gray)]:
    counts = np.array([x[key] for x in cases])
    ax.barh(ys,counts,left=left,color=color,label=label,height=.55,zorder=3)
    for y,n,start in zip(ys,counts,left):
        if n>=15:
            ax.text(start+n/2,y,str(n),ha='center',va='center',fontsize=10,
                    color='white' if color!=gray else '#45596e')
    left += counts
ax.set_yticks(ys,[f"{name}\n成功{x['successful_requests']} / 超时{x['request_errors']} / 未发{x['not_dispatched_busy_ticks']}"
                  for name,x in zip(names,cases)],fontsize=10)
ax.invert_yaxis();ax.set_xlim(0,400);ax.set_xticks([0,100,200,300,400])
ax.set_xlabel('请求数');ax.grid(axis='x',alpha=.15,zorder=0)
ax.legend(loc='upper center',bbox_to_anchor=(.5,-.17),ncol=3,frameon=False,fontsize=9)

ax = axes[1,0]
ax.set_title('C  已发请求的 P99 响应时间',loc='left',pad=15)
x = np.arange(2)
old = [cases[0]['response_ms']['p99'],cases[2]['response_ms']['p99']]
new = [cases[1]['response_ms']['p99'],cases[3]['response_ms']['p99']]
for delta,series,color,label in [(-.17,old,purple,'旧服务端'),(.17,new,green,'修复两端')]:
    ax.bar(x+delta,series,width=.30,color=color,label=label,zorder=3)
    for xx,v in zip(x+delta,series):
        ax.text(xx,v+85,f'{v:,.0f} ms',ha='center',fontsize=10,fontweight='bold')
ax.set_xticks(x,['10 ms 正态抖动','200 ms 延迟尖峰'])
ax.set_ylim(0,4550);ax.set_ylabel('毫秒');ax.grid(axis='y',alpha=.2,zorder=0)
ax.legend(loc='upper right',frameon=False,fontsize=10)
ax.text(0,-.20,'4 秒超时计入；未发出的请求数量见图 B。',transform=ax.transAxes,fontsize=10,color='#61778b')

ax = axes[1,1]
ax.set_title('D  抖动期间：目标每秒收到的上传数据',loc='left',pad=15)
for item,color,label in [(cases[0],purple,'旧服务端'),(cases[1],green,'修复两端')]:
    series=item['upload_per_second']
    ax.plot([p['end_s'] for p in series],[p['Mbit_per_second'] for p in series],
            color=color,lw=2.2,marker='o',ms=3,
            label=f"{label}（20 秒平均 {item['target_upload_Mbps']:.1f} Mbps）")
ax.set_xlim(.7,20.3);ax.set_ylim(-20,1050)
ax.set_xticks([1,5,10,15,20]);ax.set_xlabel('测量时间（秒）');ax.set_ylabel('Mbps')
ax.grid(alpha=.18);ax.legend(loc='center right',frameon=False,fontsize=10)

fig.text(.16,.054,'线路：每方向 20 ms 基础延迟，队列 8192 包；仅路由器设置 1 Gbps，代理带宽参数保持原值。',fontsize=10,color='#61778b')
fig.text(.16,.030,'对照客户端已修复 ACK 扣账并移除客户端 RTT 保护；对照 Xray 为原版。新版本仅在隔离环境验证，线上未替换。',fontsize=10,color='#61778b')
fig.savefig(STEM.with_suffix('.png'),dpi=150,facecolor='white')
fig.savefig(STEM.with_suffix('.svg'),facecolor='white')
svg = STEM.with_suffix('.svg')
svg.write_text('\n'.join(line.rstrip() for line in svg.read_text().splitlines())+'\n')
