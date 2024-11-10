import sys
import base64
import json
import yaml
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                            QHBoxLayout, QLabel, QLineEdit, QPushButton, 
                            QComboBox, QTextEdit, QFileDialog, QMessageBox,
                            QTabWidget)
from PyQt6.QtCore import Qt
from urllib.parse import unquote, quote

class SubscriptionConverter(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("本地订阅转换工具 v1.0 - by YouTube 科技共享")
        self.setMinimumSize(800, 600)
        
        # 创建主窗口部件
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout(main_widget)
        
        # 添加版本信息标签
        version_label = QLabel("本地订阅转换工具 v1.0\n作者：YouTube 科技共享")
        version_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(version_label)
        
        # 创建标签页
        tab_widget = QTabWidget()
        layout.addWidget(tab_widget)
        
        # 文件导入标签页
        file_tab = QWidget()
        file_layout = QVBoxLayout(file_tab)
        
        # 输入文件选择
        input_layout = QHBoxLayout()
        self.input_path = QLineEdit()
        self.input_path.setPlaceholderText("选择订阅文件路径...")
        browse_btn = QPushButton("浏览")
        browse_btn.clicked.connect(self.browse_file)
        input_layout.addWidget(QLabel("输入文件:"))
        input_layout.addWidget(self.input_path)
        input_layout.addWidget(browse_btn)
        file_layout.addLayout(input_layout)
        
        # 添加文件转换按钮
        file_convert_btn = QPushButton("转换文件")
        file_convert_btn.clicked.connect(self.convert_file)
        file_layout.addWidget(file_convert_btn)
        
        tab_widget.addTab(file_tab, "文件入")
        
        # 直接输入标签页
        input_tab = QWidget()
        input_layout = QVBoxLayout(input_tab)
        
        # 节点输入区域
        input_layout.addWidget(QLabel("直接输入节点信息:"))
        self.node_input = QTextEdit()
        self.node_input.setPlaceholderText("在此输入节点信息...\n支持以下格式：\n1. Base64编码的订阅内容\n2. Clash配置\n3. JSON格式")
        input_layout.addWidget(self.node_input)
        
        # 添加直接输入转换按钮
        direct_convert_btn = QPushButton("转换输入")
        direct_convert_btn.clicked.connect(self.convert_input)
        input_layout.addWidget(direct_convert_btn)
        
        tab_widget.addTab(input_tab, "直接输入")
        
        # 公共部分
        common_widget = QWidget()
        common_layout = QVBoxLayout(common_widget)
        
        # 转换格式选择
        format_layout = QHBoxLayout()
        self.format_combo = QComboBox()
        self.format_combo.addItems(["Clash", "Base64", "JSON"])
        format_layout.addWidget(QLabel("输出格式:"))
        format_layout.addWidget(self.format_combo)
        common_layout.addLayout(format_layout)
        
        # 输出结果显示
        common_layout.addWidget(QLabel("转换结果:"))
        self.result_text = QTextEdit()
        self.result_text.setReadOnly(True)
        common_layout.addWidget(self.result_text)
        
        # 保存、复制和清除按钮
        button_layout = QHBoxLayout()
        save_btn = QPushButton("保存结果")
        save_btn.clicked.connect(self.save_result)
        copy_btn = QPushButton("复制结果")
        copy_btn.clicked.connect(self.copy_result)
        clear_btn = QPushButton("清除结果")
        clear_btn.clicked.connect(self.clear_result)
        button_layout.addWidget(save_btn)
        button_layout.addWidget(copy_btn)
        button_layout.addWidget(clear_btn)
        common_layout.addLayout(button_layout)
        
        layout.addWidget(common_widget)

    def browse_file(self):
        file_name, _ = QFileDialog.getOpenFileName(
            self, "选择订阅文件", "", 
            "所有文件 (*);;文本文件 (*.txt);;YAML文件 (*.yaml *.yml)"
        )
        if file_name:
            self.input_path.setText(file_name)

    def convert_file(self):
        try:
            input_file = self.input_path.text()
            if not input_file:
                QMessageBox.warning(self, "警告", "请选择输入文件！")
                return
                
            with open(input_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            self.convert_content(content)
            
        except Exception as e:
            QMessageBox.critical(self, "错误", f"转换文件时出错：{str(e)}")

    def convert_input(self):
        try:
            content = self.node_input.toPlainText()
            if not content:
                QMessageBox.warning(self, "警告", "请输入节点信息！")
                return
            
            self.convert_content(content)
            
        except Exception as e:
            QMessageBox.critical(self, "错误", f"转换输入时出错：{str(e)}")

    def convert_content(self, content):
        try:
            # 首先检测输入格式并解析内容
            input_data = self.parse_input(content)
            if not input_data:
                return
            
            # 根据选择的输出格式进行转换
            output_format = self.format_combo.currentText().lower()
            result = self.convert_to_format(input_data, output_format)
            
            if result:
                self.result_text.setText(result)
            else:
                QMessageBox.warning(self, "错误", "转换失败！")
            
        except Exception as e:
            QMessageBox.critical(self, "错误", f"转换过程中出现错误：{str(e)}")

    def parse_input(self, content):
        """解析输入内容，统一转换为内部节点列表格式"""
        try:
            # 首先尝试解析单个节点
            if content.strip().startswith(('ss://', 'vmess://', 'trojan://', 'vless://')):
                nodes = self.parse_uri_list(content)
                if nodes:
                    return nodes

            # 尝试Base64解码
            try:
                decoded_content = base64.b64decode(content).decode('utf-8')
                # 检查是否是 Base64 编码的节点列表
                if any(line.strip().startswith(('ss://', 'vmess://', 'trojan://', 'vless://')) 
                      for line in decoded_content.splitlines()):
                    return self.parse_uri_list(decoded_content)
            except:
                pass

            # 尝试解析为 Clash 配置
            try:
                yaml_content = yaml.safe_load(content)
                if isinstance(yaml_content, dict) and 'proxies' in yaml_content:
                    return self.parse_clash_config(yaml_content)
            except:
                pass

            # 尝试解析 JSON
            try:
                json_content = json.loads(content)
                if isinstance(json_content, list):
                    return json_content
                elif isinstance(json_content, dict) and 'proxies' in json_content:
                    return json_content['proxies']
            except:
                pass

            # 尝试解析多行节点列表
            if any(line.strip().startswith(('ss://', 'vmess://', 'trojan://', 'vless://')) 
                   for line in content.splitlines()):
                return self.parse_uri_list(content)

            QMessageBox.warning(self, "错误", "无法识别输入格式！")
            return None

        except Exception as e:
            QMessageBox.critical(self, "错误", f"解析输入内容时出错：{str(e)}")
            return None

    def parse_uri_list(self, content):
        """解析 URI 格式的节点列表"""
        nodes = []
        used_names = set()  # 用于追踪已使用的节点名称
        
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
                
            try:
                node = None
                if line.startswith('ss://'):
                    node = self.parse_ss_uri(line)
                elif line.startswith('vmess://'):
                    node = self.parse_vmess_uri(line)
                elif line.startswith('trojan://'):
                    node = self.parse_trojan_uri(line)
                elif line.startswith('vless://'):  # 添加 VLESS 支持
                    node = self.parse_vless_uri(line)
                
                if node:
                    # 确保节点名称唯一
                    original_name = node['name']
                    counter = 1
                    while node['name'] in used_names:
                        node['name'] = f"{original_name}-{counter}"
                        counter += 1
                    used_names.add(node['name'])
                    nodes.append(node)
            except Exception as e:
                print(f"解析节点失败: {line}, 错误: {str(e)}")
                
        return nodes

    def parse_clash_config(self, config):
        """解析 Clash 配置"""
        if 'proxies' not in config:
            return []
            
        proxies = config['proxies']
        used_names = set()
        
        # 确保所有节点名称唯一
        for proxy in proxies:
            original_name = proxy.get('name', '')
            counter = 1
            while proxy['name'] in used_names:
                proxy['name'] = f"{original_name}-{counter}"
                counter += 1
            used_names.add(proxy['name'])
        
        return proxies

    def convert_to_format(self, nodes, output_format):
        """将节点转换为指定格式"""
        if not nodes:
            return None

        try:
            if output_format == "clash":
                return self.to_clash(nodes)
            elif output_format == "base64":
                return self.to_base64(nodes)
            elif output_format == "json":
                return self.to_json(nodes)
        except Exception as e:
            print(f"转换格式失败: {str(e)}")
            return None

    def to_clash(self, nodes):
        """转换为 Clash 配置格式"""
        config = {
            "port": 7890,
            "socks-port": 7891,
            "allow-lan": True,
            "mode": "rule",
            "log-level": "info",
            "external-controller": "127.0.0.1:9090",
            "external-ui": "yacd",
            "secret": "",
            "dns": {
                "enable": True,
                "listen": "0.0.0.0:53",
                "enhanced-mode": "fake-ip",
                "nameserver": [
                    "114.114.114.114",
                    "223.5.5.5",
                    "8.8.8.8",
                    "8.8.4.4"
                ]
            },
            "tcp-concurrent": True,
            "proxies": nodes,
            "proxy-groups": [
                {
                    "name": "🚀 节点选择",
                    "type": "select",
                    "proxies": ["♻️ 自动选择", "DIRECT"] + [node.get('name', '') for node in nodes]
                },
                {
                    "name": "♻️ 自动选择",
                    "type": "url-test",
                    "url": "http://www.gstatic.com/generate_204",
                    "interval": 300,
                    "tolerance": 50,
                    "proxies": [node.get('name', '') for node in nodes]
                },
                {
                    "name": "🌍 国外媒体",
                    "type": "select",
                    "proxies": ["🚀 节点选择", "♻️ 自动选择", "DIRECT"] + [node.get('name', '') for node in nodes]
                },
                {
                    "name": "📲 电报信息",
                    "type": "select",
                    "proxies": ["🚀 节点选择", "♻️ 自动选择"] + [node.get('name', '') for node in nodes]
                },
                {
                    "name": "Ⓜ️ 微软服务",
                    "type": "select",
                    "proxies": ["🚀 节点选择", "DIRECT"]
                },
                {
                    "name": "🍎 苹果服务",
                    "type": "select",
                    "proxies": ["DIRECT", "🚀 节点选择"]
                },
                {
                    "name": "🎯 全球直连",
                    "type": "select",
                    "proxies": ["DIRECT", "🚀 节点选择"]
                },
                {
                    "name": "🛑 全球拦截",
                    "type": "select",
                    "proxies": ["REJECT", "DIRECT"]
                }
            ],
            "rules": [
                "DOMAIN-SUFFIX,google.com,🚀 节点选择",
                "DOMAIN-SUFFIX,facebook.com,🚀 节点选择",
                "DOMAIN-SUFFIX,twitter.com,🚀 节点选择",
                "DOMAIN-SUFFIX,youtube.com,🚀 节点选择",
                "DOMAIN-SUFFIX,telegram.org,📲 电报信息",
                "DOMAIN-SUFFIX,microsoft.com,Ⓜ️ 微软服务",
                "DOMAIN-SUFFIX,apple.com,🍎 苹果服务",
                "DOMAIN-SUFFIX,icloud.com,🍎 苹果服务",
                "DOMAIN-SUFFIX,netflix.com,🌍 国外媒体",
                "DOMAIN-SUFFIX,hulu.com,🌍 国外媒体",
                "DOMAIN-SUFFIX,amazonaws.com,🚀 节点选择",
                "DOMAIN-SUFFIX,azure.com,🚀 节点选择",
                "DOMAIN-SUFFIX,cloudflare.com,🚀 节点选择",
                "DOMAIN-SUFFIX,cn,🎯 全球直连",
                "GEOIP,CN,🎯 全球直连",
                "MATCH,🚀 节点选择"
            ]
        }
        return yaml.dump(config, allow_unicode=True, sort_keys=False)

    def to_base64(self, nodes):
        """转换为 Base64 格式"""
        uri_list = []
        for node in nodes:
            if node.get('type') == 'ss':
                uri_list.append(self.to_ss_uri(node))
            elif node.get('type') == 'vmess':
                uri_list.append(self.to_vmess_uri(node))
            elif node.get('type') == 'trojan':
                uri_list.append(self.to_trojan_uri(node))
        
        content = '\n'.join(uri_list)
        return base64.b64encode(content.encode()).decode()

    def to_json(self, nodes):
        """转换为 JSON 格式"""
        return json.dumps(nodes, ensure_ascii=False, indent=2)

    def parse_ss_uri(self, uri):
        """解析 Shadowsocks URI"""
        if not uri.startswith('ss://'):
            return None
        
        try:
            # 移除 'ss://' 前缀
            content = uri[5:]
            
            # 处理可能存在的备注信息
            if '#' in content:
                content, remark = content.split('#', 1)
                try:
                    remark = unquote(remark)  # URL解码备注信息
                except:
                    pass
            else:
                remark = None
            
            # 尝试两种格式的解析
            try:
                # 格式1: base64(method:password)@hostname:port
                if '@' in content:
                    user_info, server_info = content.split('@', 1)
                    try:
                        # 尝试解码 user_info 部分
                        decoded_user_info = base64.b64decode(user_info).decode()
                        method, password = decoded_user_info.split(':', 1)
                    except:
                        # 如果解码失败，可能整个用户信息都是 base64 编码的
                        decoded_content = base64.b64decode(content.replace('@', '')).decode()
                        method, password = decoded_content.split(':', 1)
                        server_info = content.split('@', 1)[1]
                    
                    server, port = server_info.split(':', 1)
                else:
                    # 格式2: base64(method:password@hostname:port)
                    decoded = base64.b64decode(content).decode()
                    if '@' in decoded:
                        user_pass, server_info = decoded.split('@', 1)
                        method, password = user_pass.split(':', 1)
                        server, port = server_info.split(':', 1)
                    else:
                        raise ValueError("Invalid SS URI format")
                
                # 修改节点名称格式
                name = self.format_node_name(remark if remark else f"SS-{server}")
                
                return {
                    'type': 'ss',
                    'name': name,
                    'server': server,
                    'port': int(port),
                    'cipher': method,
                    'password': password,
                    'udp': True
                }
            except Exception as e:
                print(f"SS URI 解析错误: {str(e)}")
                return None
                
        except Exception as e:
            print(f"SS URI 解析失败: {str(e)}")
            return None

    def parse_vmess_uri(self, uri):
        """解析 VMess URI"""
        if not uri.startswith('vmess://'):
            return None
        
        try:
            # 除 'vmess://' 前缀并解码
            content = uri[8:]
            config = json.loads(base64.b64decode(content).decode())
            
            # 使用更多信息生成唯一的节点名称
            name = self.format_node_name(config.get('ps', f"VMess-{config.get('add')}"))
            
            # 构建 Clash 格式的 VMess 配置
            vmess_config = {
                'type': 'vmess',
                'name': name,
                'server': config.get('add', ''),
                'port': int(config.get('port', 0)),
                'uuid': config.get('id', ''),
                'alterId': int(config.get('aid', 0)),
                'cipher': config.get('scy', 'auto'),
                'udp': True,
                'skip-cert-verify': True  # 添加跳过证书验证
            }

            # 处理传输协议
            network = config.get('net', 'tcp')
            vmess_config['network'] = network

            # TLS 设置
            if config.get('tls') == 'tls':
                vmess_config['tls'] = True
            
            # SNI 设置
            if config.get('sni'):
                vmess_config['servername'] = config.get('sni')
            elif config.get('host'):
                vmess_config['servername'] = config.get('host')

            # 根据不同传输协议添加特定配置
            if network == 'ws':
                ws_opts = {
                    'path': config.get('path', '/'),
                }
                # 设置 Host
                if config.get('host'):
                    ws_opts['headers'] = {
                        'Host': config.get('host')
                    }
                vmess_config['ws-opts'] = ws_opts
            elif network == 'h2':
                vmess_config['h2-opts'] = {
                    'host': [config.get('host', '')],
                    'path': config.get('path', '/')
                }
            elif network == 'http':
                vmess_config['http-opts'] = {
                    'path': [config.get('path', '/')],
                    'headers': {
                        'Host': [config.get('host', '')]
                    }
                }
            elif network == 'grpc':
                vmess_config['grpc-opts'] = {
                    'grpc-service-name': config.get('path', '')
                }

            return vmess_config
            
        except Exception as e:
            print(f"解析 VMess 配置失败: {str(e)}")
            return None

    def parse_trojan_uri(self, uri):
        """解析 Trojan URI"""
        if not uri.startswith('trojan://'):
            return None
        
        try:
            # 移除 'trojan://' 前缀
            content = uri[9:]
            password, server_info = content.split('@', 1)
            server, port = server_info.split(':', 1)
            
            # 生成唯一的节点名称
            name = self.format_node_name(f"Trojan-{server}")
            
            return {
                'type': 'trojan',
                'name': name,
                'server': server,
                'port': int(port),
                'password': password
            }
        except:
            pass
        return None

    def to_ss_uri(self, node):
        """转换为 Shadowsocks URI"""
        if node['type'] != 'ss':
            return None
        
        user_info = base64.b64encode(
            f"{node['cipher']}:{node['password']}".encode()
        ).decode()
        return f"ss://{user_info}@{node['server']}:{node['port']}"

    def to_vmess_uri(self, node):
        """转换为 VMess URI"""
        if node['type'] != 'vmess':
            return None
        
        config = {
            'v': '2',
            'ps': node['name'],
            'add': node['server'],
            'port': str(node['port']),
            'id': node['uuid'],
            'aid': str(node['alterId']),
            'net': node.get('network', 'tcp'),
            'type': 'none',
            'host': '',
            'path': '',
            'tls': 'tls' if node.get('tls', False) else ''
        }

        # 处理不同传输协议的配置
        if node.get('network') == 'ws':
            if 'ws-opts' in node:
                config['path'] = node['ws-opts'].get('path', '')
                config['host'] = node['ws-opts'].get('headers', {}).get('Host', '')
        elif node.get('network') == 'h2':
            if 'h2-opts' in node:
                config['path'] = node['h2-opts'].get('path', '')
                config['host'] = node['h2-opts'].get('host', [''])[0]
        elif node.get('network') == 'http':
            if 'http-opts' in node:
                config['path'] = node['http-opts'].get('path', [''])[0]
                config['host'] = node['http-opts'].get('headers', {}).get('Host', [''])[0]
        elif node.get('network') == 'grpc':
            if 'grpc-opts' in node:
                config['path'] = node['grpc-opts'].get('grpc-service-name', '')

        return f"vmess://{base64.b64encode(json.dumps(config).encode()).decode()}"

    def to_trojan_uri(self, node):
        """转换为 Trojan URI"""
        if node['type'] != 'trojan':
            return None
        
        return f"trojan://{node['password']}@{node['server']}:{node['port']}"

    def save_result(self):
        if not self.result_text.toPlainText():
            QMessageBox.warning(self, "警告", "没有可保存的内容！")
            return
        
        # 根据当前选择的格式设置默认保存格式
        output_format = self.format_combo.currentText().lower()
        if output_format == "clash":
            file_filter = "YAML文件 (*.yaml);;所有文件 (*)"
            default_ext = ".yaml"
        elif output_format == "json":
            file_filter = "JSON文件 (*.json);;所有文件 (*)"
            default_ext = ".json"
        else:
            file_filter = "文本文件 (*.txt);;所有文件 (*)"
            default_ext = ".txt"
            
        file_name, _ = QFileDialog.getSaveFileName(
            self, "保存文件", "", file_filter
        )
        
        if file_name:
            # 如果用户没有输入扩展名，自动添加对应的扩展名
            if not any(file_name.endswith(ext) for ext in ['.yaml', '.yml', '.json', '.txt']):
                file_name += default_ext
                
            try:
                with open(file_name, 'w', encoding='utf-8') as f:
                    f.write(self.result_text.toPlainText())
                QMessageBox.information(self, "成功", "文件保存成功！")
            except Exception as e:
                QMessageBox.critical(self, "错误", f"保存文件时出错：{str(e)}")

    def copy_result(self):
        if not self.result_text.toPlainText():
            QMessageBox.warning(self, "警告", "没有可复制的内容！")
            return
        
        clipboard = QApplication.clipboard()
        clipboard.setText(self.result_text.toPlainText())
        QMessageBox.information(self, "成功", "已复制到剪贴板！")

    def clear_result(self):
        """清除转换结果"""
        self.result_text.clear()

    def parse_vless_uri(self, uri):
        """解析 VLESS URI 并转换为 Clash.Meta/mihomo 格式"""
        if not uri.startswith('vless://'):
            return None
        
        try:
            # 移除 'vless://' 前缀
            content = uri[8:]
            
            # 分离用户信息和查询参数
            if '#' in content:
                content, remark = content.split('#', 1)
                remark = unquote(remark)
            else:
                remark = None
            
            # 分离主机信息和参数
            if '?' in content:
                main_part, query_part = content.split('?', 1)
            else:
                main_part, query_part = content, ''
            
            # 解析主要部分
            uuid, server_info = main_part.split('@', 1)
            server, port = server_info.split(':', 1)
            
            # 解析查询参数
            from urllib.parse import parse_qs
            params = parse_qs(query_part)
            
            # 构建 Clash.Meta/mihomo 格式的 VLESS 配置
            vless_config = {
                'type': 'vless',
                'name': self.format_node_name(remark if remark else f"VLESS-{server}"),
                'server': server,
                'port': int(port),
                'uuid': uuid,
                'udp': True,
                'skip-cert-verify': True,
                'client-fingerprint': params.get('fp', ['chrome'])[0],  # 添加指纹
                'flow': params.get('flow', [''])[0]  # 添加 flow
            }
            
            # 处理传输协议
            if 'type' in params:
                network = params['type'][0]
                vless_config['network'] = network
                
                if network == 'ws':
                    ws_opts = {}
                    if 'path' in params:
                        ws_opts['path'] = unquote(params['path'][0])
                    if 'host' in params:
                        ws_opts['headers'] = {'Host': params['host'][0]}
                    vless_config['ws-opts'] = ws_opts
            
            # TLS 设置
            if 'security' in params and params['security'][0] == 'tls':
                vless_config['tls'] = True
                if 'sni' in params:
                    vless_config['servername'] = params['sni'][0]
                if 'alpn' in params:
                    vless_config['alpn'] = [x.strip() for x in params['alpn'][0].split(',')]
                if 'fp' in params:
                    vless_config['client-fingerprint'] = params['fp'][0]
            
            return vless_config
            
        except Exception as e:
            print(f"VLESS URI 解析失败: {str(e)}")
            return None

    def to_vless_uri(self, node):
        """转换为 VLESS URI"""
        if node['type'] != 'vless':
            return None
        
        # 构建基本 URI
        uri = f"vless://{node['uuid']}@{node['server']}:{node['port']}"
        
        # 构建查询参数
        params = []
        params.append('encryption=none')  # VLESS 必需参数
        
        if node.get('tls'):
            params.append('security=tls')
            if node.get('servername'):
                params.append(f"sni={node['servername']}")
            if node.get('alpn'):
                params.append(f"alpn={','.join(node['alpn'])}")
        
        if node.get('network'):
            params.append(f"type={node['network']}")
            if node['network'] == 'ws' and 'ws-opts' in node:
                if 'path' in node['ws-opts']:
                    params.append(f"path={quote(node['ws-opts']['path'])}")
                if 'headers' in node['ws-opts'] and 'Host' in node['ws-opts']['headers']:
                    params.append(f"host={node['ws-opts']['headers']['Host']}")
        
        # 添加查询参数和备注
        uri += '?' + '&'.join(params)
        if node.get('name'):
            uri += '#' + quote(node['name'])
        
        return uri

    def format_node_name(self, original_name):
        """格式化节点名称，添加地区标识和作者信息"""
        # 地区代码映射
        region_codes = {
            'HK': '[HK]', '香港': '[HK]', 'Hong Kong': '[HK]',
            'TW': '[TW]', '台湾': '[TW]', 'Taiwan': '[TW]',
            'JP': '[JP]', '日本': '[JP]', 'Japan': '[JP]',
            'SG': '[SG]', '新加坡': '[SG]', 'Singapore': '[SG]',
            'US': '[US]', '美国': '[US]', 'United States': '[US]',
            'KR': '[KR]', '韩国': '[KR]', 'Korea': '[KR]',
            # 可以继续添加其他地区
        }
        
        # 提取地区标识
        region_code = ''
        for code, prefix in region_codes.items():
            if any(identifier in original_name for identifier in [code, prefix]):
                region_code = prefix
                break
        
        # 如果没有找到地区标识，使用 [UN] 表示未知
        if not region_code:
            region_code = '[UN]'
        
        return f"{region_code}YouTube 科技共享"

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = SubscriptionConverter()
    window.show()
    sys.exit(app.exec())