from graphviz import Digraph

dot = Digraph('NetworkTopology', format='png')
dot.attr(rankdir='TB', splines='ortho', nodesep='0.8')
dot.attr('node', shape='box', style='filled', fillcolor='#f9f9f9', fontname='Consolas')

# Client
with dot.subgraph(name='cluster_client') as c:
    c.attr(label='ns_client', style='dashed', fillcolor='#e6f2ff')
    c.node('client', 'iface: veth_c\nIP: 20.0.1.100/24\nroute: 10.0.1.0/24 via 20.0.1.1')

# Router
with dot.subgraph(name='cluster_router') as c:
    c.attr(label='ns_router (라우팅 전담)', style='dashed', fillcolor='#fff2e6')
    c.node('router_c', 'iface: veth_r_c\nIP: 20.0.1.1/24')
    c.node('router_p', 'iface: veth_r_p\nIP: 10.0.1.1/24')
    c.node('router_sysctl', 'sysctl: net.ipv4.ip_forward=1', shape='plaintext', fillcolor='none')

# Proxy
with dot.subgraph(name='cluster_proxy') as c:
    c.attr(label='ns_proxy (브리지 + TPROXY 전담)', style='dashed', fillcolor='#e6ffe6')
    c.node('proxy_r', 'port: veth_p_r')
    c.node('proxy_br0', 'bridge: br0', shape='ellipse')
    c.node('proxy_s', 'port: veth_p_s')
    c.node('proxy_rules', 
           'sysctl: net.ipv4.ip_forward=0\n'
           'TPROXY target: 20.0.1.100 -> 10.0.1.100:8080 => local :50080\n'
           'ip rule: fwmark 0x1 lookup table 100\n'
           'table100: local 0.0.0.0/0 dev lo', shape='note', fillcolor='#ffffff')
    
    c.edge('proxy_r', 'proxy_br0', dir='none')
    c.edge('proxy_s', 'proxy_br0', dir='none')

# Server
with dot.subgraph(name='cluster_server') as c:
    c.attr(label='ns_server', style='dashed', fillcolor='#ffe6e6')
    c.node('server', 'iface: veth_s\nIP: 10.0.1.100/24\nroute: 20.0.1.0/24 via 10.0.1.1\nservice: TCP 8080')

# Connections (veth pairs)
dot.edge('client', 'router_c', label=' veth pair', dir='both')
dot.edge('router_p', 'proxy_r', label=' veth pair', dir='both')
dot.edge('proxy_s', 'server', label=' veth pair', dir='both')

dot.render('network_topology', view=True)
print("network_topology.png 파일이 생성되었습니다.")