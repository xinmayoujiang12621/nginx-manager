import os
from datetime import datetime
import OpenSSL.crypto as crypto

class CertManager:
    def __init__(self):
        self.cert_path = None
        self.key_path = None
    
    def load_certificate(self, cert_path):
        """加载SSL证书"""
        self.cert_path = cert_path
        try:
            with open(cert_path, 'rb') as f:
                cert_data = f.read()
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_data)
            return cert
        except Exception as e:
            raise Exception(f"证书加载失败: {str(e)}")
    
    def get_cert_info(self, cert_path):
        """获取证书信息"""
        cert = self.load_certificate(cert_path)
        return {
            'subject': dict(cert.get_subject().get_components()),
            'issuer': dict(cert.get_issuer().get_components()),
            'not_before': datetime.strptime(cert.get_notBefore().decode(), '%Y%m%d%H%M%SZ'),
            'not_after': datetime.strptime(cert.get_notAfter().decode(), '%Y%m%d%H%M%SZ'),
            'serial_number': cert.get_serial_number()
        }
    
    def check_expiry(self, cert_path, warning_days=30):
        """检查证书是否即将过期"""
        cert_info = self.get_cert_info(cert_path)
        remaining_days = (cert_info['not_after'] - datetime.now()).days
        return remaining_days <= warning_days, remaining_days 