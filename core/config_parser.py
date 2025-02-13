from pyparsing import *
import sys
from typing import List, Union, Optional, Dict
import copy

class NginxConfigParser:
    def __init__(self):
        # 增加递归限制
        sys.setrecursionlimit(3000)  # 默认是1000
        self.config_tree = None
        self.context_stack = []  # 用于跟踪当前上下文
        self._setup_grammar()

    def _setup_grammar(self):
        """设置Nginx配置文件解析规则"""
        # 基本元素
        self.LBRACE, self.RBRACE, self.SEMI = map(Suppress, "{};")
        
        # 注释
        self.COMMENT = Group(
            Literal("#").suppress() + 
            restOfLine
        ).setResultsName("comment")
        
        # 变量引用
        self.variable = Combine("$" + Word(alphas + "_", alphanums + "_"))
        
        # 指令值支持的特殊字符
        special_chars = ".-+*=~!@#$%^&()[]<>,:/'_"
        
        # 指令名称
        self.directive_name = Word(alphas + "_", alphanums + "_-")
        
        # 指令值（支持更多格式）
        self.directive_value = (
            self.variable |
            QuotedString('"', escChar='\\') |
            QuotedString("'", escChar='\\') |
            Word(alphanums + special_chars) |
            Combine(OneOrMore(Word(printables, excludeChars="{};#\\")))
        )
        
        # 简单指令
        self.simple_directive = Group(
            self.directive_name +
            ZeroOrMore(self.directive_value) +
            self.SEMI
        ).setName("directive")
        
        # 块指令
        self.block = Forward()
        
        # 配置行 - 包括注释、指令和块
        self.config_line = (
            self.COMMENT |
            self.simple_directive |
            self.block
        )
        
        # 块内容
        self.block_body = Group(
            ZeroOrMore(self.config_line)
        )
        
        # 修改块的定义
        self.block << Group(
            self.directive_name +
            ZeroOrMore(self.directive_value) +
            self.LBRACE +
            self.block_body +
            self.RBRACE
        ).setName("block")
        
        # 完整的配置文件语法
        self.grammar = ZeroOrMore(self.config_line)

    def parse(self, config_str: str) -> ParseResults:
        """解析配置文件内容"""
        try:
            self.config_tree = self.grammar.parseString(config_str, parseAll=True)
            return self.config_tree
        except ParseException as e:
            raise Exception(f"配置解析错误 (行 {e.lineno}, 列 {e.column}): {str(e)}")
        except RecursionError:
            raise Exception("配置文件结构过于复杂，解析失败")

    def validate(self, config_str):
        """验证配置文件语法"""
        try:
            # 使用更简单的验证方法
            lines = config_str.split('\n')
            brace_count = 0
            
            for i, line in enumerate(lines, 1):
                line = line.strip()
                
                # 跳过空行和注释
                if not line or line.startswith('#'):
                    continue
                
                # 计算花括号
                brace_count += line.count('{') - line.count('}')
                
                # 检查基本语法
                if line.endswith('{'):
                    if not any(char.isalpha() for char in line):
                        return False, f"行 {i}: 无效的块开始"
                elif line.endswith(';'):
                    if not any(char.isalpha() for char in line):
                        return False, f"行 {i}: 无效的指令"
                elif line == '}':
                    continue
                elif not (line.endswith('{') or line.endswith(';') or line.endswith('}')):
                    return False, f"行 {i}: 缺少分号或花括号"
            
            # 检查花括号匹配
            if brace_count != 0:
                return False, "花括号不匹配"
            
            return True, None
            
        except Exception as e:
            return False, str(e)

    def find_blocks(self, block_type: str) -> List[ParseResults]:
        """查找指定类型的配置块"""
        blocks = []
        
        def traverse(node):
            if isinstance(node, ParseResults):
                if len(node) > 0 and node[0] == block_type:
                    blocks.append(node)
                for item in node:
                    if isinstance(item, ParseResults):
                        traverse(item)
        
        if self.config_tree:
            traverse(self.config_tree)
        return blocks

    def find_directives(self, directive_name):
        """查找指定名称的指令"""
        if not self.config_tree:
            return []
        
        directives = []
        def traverse(node):
            if isinstance(node, ParseResults):
                if len(node) > 0 and node[0] == directive_name:
                    directives.append(node[1:])
                for item in node:
                    if isinstance(item, ParseResults):
                        traverse(item)
                    
        traverse(self.config_tree)
        return directives

    def to_string(self, tree: Optional[ParseResults] = None, indent: int = 0) -> str:
        """将解析树转换为配置文件格式"""
        if tree is None:
            tree = self.config_tree
            
        result = []
        indent_str = "    " * indent
        
        for item in tree:
            if isinstance(item, ParseResults):
                if len(item) == 0:
                    continue
                    
                # 处理注释
                if item.getName() == "comment":
                    result.append(f"{indent_str}#{item[0]}")
                    continue
                    
                if isinstance(item[-1], ParseResults):
                    # 这是一个块
                    block_header = " ".join(str(x) for x in item[:-1])
                    result.append(f"{indent_str}{block_header} {{")
                    result.append(self.to_string(item[-1], indent + 1))
                    result.append(f"{indent_str}}}")
                else:
                    # 这是一个指令
                    directive_str = " ".join(str(x) for x in item)
                    result.append(f"{indent_str}{directive_str};")
                    
        return "\n".join(result)

    def find_server_blocks(self):
        """查找所有server块配置"""
        if not self.config_tree:
            return []
        
        server_blocks = []
        def traverse(node):
            if isinstance(node, list) and len(node) > 0:
                if node[0] == 'server':
                    server_blocks.append(node)
                for item in node:
                    traverse(item)
                    
        traverse(self.config_tree)
        return server_blocks

    def add_block(self, parent_type: str, block_content: str) -> bool:
        """添加新的配置块到指定类型的父块中"""
        try:
            # 解析新块的内容
            new_block = self.grammar.parseString(block_content, parseAll=True)[0]
            
            # 查找父块
            parent_blocks = self.find_blocks(parent_type)
            if not parent_blocks:
                raise Exception(f"未找到类型为 {parent_type} 的父块")
            
            # 添加到第一个找到的父块中
            parent_block = parent_blocks[0]
            if len(parent_block) > 0 and isinstance(parent_block[-1], ParseResults):
                parent_block[-1].append(new_block)
            return True
        except Exception as e:
            raise Exception(f"添加配置块失败: {str(e)}")

    def remove_block(self, block: ParseResults) -> bool:
        """删除指定的配置块"""
        def remove_from_tree(node):
            if isinstance(node, ParseResults):
                for i, item in enumerate(node):
                    if isinstance(item, ParseResults):
                        if item is block:
                            del node[i]
                            return True
                        if remove_from_tree(item):
                            return True
            return False
        
        if self.config_tree:
            return remove_from_tree(self.config_tree)
        return False

    def update_block(self, old_block: ParseResults, new_content: str) -> bool:
        """更新配置块的内容"""
        try:
            # 解析新内容
            new_block = self.grammar.parseString(new_content, parseAll=True)[0]
            
            def update_in_tree(node):
                if isinstance(node, ParseResults):
                    for i, item in enumerate(node):
                        if isinstance(item, ParseResults):
                            if item is old_block:
                                node[i] = new_block
                                return True
                            if update_in_tree(item):
                                return True
                return False
            
            if self.config_tree:
                return update_in_tree(self.config_tree)
            return False
            
        except Exception as e:
            raise Exception(f"更新配置块失败: {str(e)}")

    def clone_block(self, block: ParseResults) -> Optional[ParseResults]:
        """克隆配置块"""
        try:
            # 将块转换为字符串
            block_str = self.to_string(block)
            # 解析字符串创建新块
            return self.grammar.parseString(block_str, parseAll=True)[0]
        except Exception as e:
            raise Exception(f"克隆配置块失败: {str(e)}")

    def get_block_directives(self, block: ParseResults, directive_name: str) -> List[ParseResults]:
        """获取块中指定名称的指令"""
        directives = []
        
        def traverse(node):
            if isinstance(node, ParseResults):
                if len(node) > 0 and node[0] == directive_name:
                    directives.append(node)
                for item in node:
                    if isinstance(item, ParseResults):
                        traverse(item)
        
        traverse(block)
        return directives

    def validate_block(self, block_content: str) -> tuple[bool, Optional[str]]:
        """验证配置块的语法"""
        try:
            self.grammar.parseString(block_content, parseAll=True)
            return True, None
        except ParseException as e:
            return False, f"语法错误 (行 {e.lineno}, 列 {e.column}): {str(e)}"
        except Exception as e:
            return False, str(e)

    def get_context_info(self, block_type: str) -> Dict:
        """获取块类型的上下文信息"""
        context_info = {
            "http": {
                "parent": ["main"],
                "children": ["server", "upstream", "location"],
                "directives": ["include", "default_type", "access_log", "error_log"]
            },
            "server": {
                "parent": ["http"],
                "children": ["location", "if"],
                "directives": ["listen", "server_name", "ssl_certificate", "root"]
            },
            "location": {
                "parent": ["server", "location"],
                "children": ["location", "if"],
                "directives": ["root", "proxy_pass", "fastcgi_pass", "try_files"]
            },
            "upstream": {
                "parent": ["http"],
                "children": [],
                "directives": ["server", "ip_hash", "least_conn"]
            }
        }
        return context_info.get(block_type, {})

    def validate_context(self, block_type: str, parent_type: str = None) -> bool:
        """验证块类型在当前上下文中是否有效"""
        context_info = self.get_context_info(block_type)
        if not context_info:
            return True  # 未知的块类型，暂时允许
            
        if parent_type:
            return parent_type in context_info["parent"]
        return True

    def validate_directive(self, directive_name: str, block_type: str) -> bool:
        """验证指令在当前块中是否有效"""
        context_info = self.get_context_info(block_type)
        if not context_info:
            return True  # 未知的块类型，暂时允许
            
        # 某些指令在所有上下文中都有效
        common_directives = ["include", "error_log", "access_log"]
        if directive_name in common_directives:
            return True
            
        return directive_name in context_info["directives"]

    def parse_directive(self, directive_text: str) -> ParseResults:
        """解析单个指令"""
        try:
            return self.simple_directive.parseString(directive_text, parseAll=True)[0]
        except ParseException as e:
            raise ValueError(f"指令语法错误: {str(e)}")

    def parse_block(self, block_content: str) -> ParseResults:
        """解析配置块"""
        try:
            # 确保内容是一个完整的块
            if not block_content.strip().endswith('}'):
                block_content = block_content.strip() + " {}"
            
            parsed = self.grammar.parseString(block_content, parseAll=True)
            if parsed and len(parsed) > 0:
                return parsed[0]
            raise ValueError("解析结果为空")
        except ParseException as e:
            raise ValueError(f"配置块语法错误：{str(e)}")

    def parse_string(self, config_string: str) -> List[ParseResults]:
        """解析配置字符串"""
        try:
            # 预处理配置字符串
            config_string = config_string.strip()
            
            # 解析整个配置字符串
            parsed = self.grammar.parseString(config_string, parseAll=True)
            
            # 转换为列表并返回
            result = []
            for item in parsed:
                if isinstance(item, ParseResults):
                    result.append(item[0])  # 解包顶级Group
            return result
            
        except ParseException as e:
            # 提供更详细的错误信息
            error_line = config_string.split('\n')[e.lineno - 1] if e.lineno > 0 else ''
            error_msg = (f"配置解析错误：\n"
                        f"位置：第 {e.lineno} 行，第 {e.column} 列\n"
                        f"错误行：{error_line}\n"
                        f"错误信息：{str(e)}")
            raise ValueError(error_msg) 