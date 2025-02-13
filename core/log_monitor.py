import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class NginxLogMonitor:
    def __init__(self, log_path):
        self.log_path = log_path
        self.observer = Observer()
        self.handler = NginxLogHandler()
        
    def start_monitoring(self):
        """开始监控日志文件"""
        self.observer.schedule(
            self.handler, 
            os.path.dirname(self.log_path), 
            recursive=False
        )
        self.observer.start() 