import psutil
import subprocess
import os

class NginxError(Exception):
    """Nginx操作相关异常基类"""
    pass

class NginxStartError(NginxError):
    """Nginx启动失败异常"""
    pass

class NginxConfigError(NginxError):
    """Nginx配置错误异常"""
    pass

class NginxManager:
    def __init__(self, nginx_path="C:/nginx/nginx.exe"):
        self.nginx_path = os.path.abspath(nginx_path)
        self.nginx_dir = os.path.dirname(self.nginx_path)
        self.process = None
        
        # 确保路径都是绝对路径
        self.config_path = os.path.join(self.nginx_dir, "conf/nginx.conf")
        self.error_log_path = os.path.join(self.nginx_dir, "logs/error.log")
        self.access_log_path = os.path.join(self.nginx_dir, "logs/access.log")

    def is_running(self):
        """检查Nginx进程状态"""
        try:
            return any("nginx.exe" in p.name() for p in psutil.process_iter())
        except:
            return False

    def start(self):
        """启动Nginx"""
        if not os.path.exists(self.nginx_path):
            raise NginxError(f"Nginx可执行文件不存在: {self.nginx_path}")

        if not self.is_running():
            try:
                # 切换到Nginx安装目录再执行命令
                original_dir = os.getcwd()
                os.chdir(self.nginx_dir)
                
                try:
                    self.process = subprocess.Popen(
                        [self.nginx_path],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        cwd=self.nginx_dir  # 设置工作目录
                    )
                    # 等待一小段时间检查进程是否成功启动
                    self.process.wait(timeout=1)
                    if self.process.returncode != 0:
                        stderr = self.process.stderr.read().decode()
                        raise NginxStartError(f"Nginx启动失败: {stderr}")
                    return True
                finally:
                    # 恢复原始工作目录
                    os.chdir(original_dir)
                    
            except subprocess.TimeoutExpired:
                # 进程没有立即退出说明启动成功
                return True
            except Exception as e:
                raise NginxStartError(f"启动Nginx时发生错误: {str(e)}")
        return False

    def stop(self):
        """停止Nginx"""
        if self.is_running():
            try:
                # 切换到Nginx安装目录再执行命令
                original_dir = os.getcwd()
                os.chdir(self.nginx_dir)
                
                try:
                    subprocess.run(
                        [self.nginx_path, "-s", "stop"],
                        check=True,
                        capture_output=True,
                        cwd=self.nginx_dir  # 设置工作目录
                    )
                    return True
                finally:
                    # 恢复原始工作目录
                    os.chdir(original_dir)
            except subprocess.CalledProcessError as e:
                raise NginxError(f"停止Nginx失败: {e.stderr.decode()}")
        return False

    def reload(self):
        """重新加载Nginx配置"""
        if self.is_running():
            try:
                # 切换到Nginx安装目录再执行命令
                original_dir = os.getcwd()
                os.chdir(self.nginx_dir)
                
                try:
                    subprocess.run(
                        [self.nginx_path, "-s", "reload"],
                        check=True,
                        capture_output=True,
                        cwd=self.nginx_dir  # 设置工作目录
                    )
                    return True
                finally:
                    # 恢复原始工作目录
                    os.chdir(original_dir)
            except subprocess.CalledProcessError as e:
                raise NginxError(f"重载Nginx配置失败: {e.stderr.decode()}")
        return False

    def test_config(self):
        """测试配置文件"""
        try:
            # 切换到Nginx安装目录再执行命令
            original_dir = os.getcwd()
            os.chdir(self.nginx_dir)
            
            try:
                result = subprocess.run(
                    [self.nginx_path, "-t"],
                    capture_output=True,
                    text=True,
                    cwd=self.nginx_dir  # 设置工作目录
                )
                return result.returncode == 0, result.stderr
            finally:
                # 恢复原始工作目录
                os.chdir(original_dir)
        except Exception as e:
            raise NginxConfigError(f"测试配置文件失败: {str(e)}")

    def get_version(self):
        """获取Nginx版本"""
        try:
            result = subprocess.run(
                [self.nginx_path, "-v"],
                capture_output=True,
                text=True,
                cwd=self.nginx_dir  # 设置工作目录
            )
            return result.stderr.strip()
        except Exception as e:
            raise NginxError(f"获取Nginx版本失败: {str(e)}") 