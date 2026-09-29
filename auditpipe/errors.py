"""统一的错误类型定义。"""


class AuditPipeError(Exception):
    """所有管道错误的基类。"""


class ValidationError(AuditPipeError):
    """事件未通过接入校验（字段缺失 / 时间异常 / 版本不兼容等）。"""


class IntegrityError(AuditPipeError):
    """存储数据的完整性校验失败。"""


class StorageError(AuditPipeError):
    """存储层错误。"""


class DeliveryError(AuditPipeError):
    """下游投递错误。"""


class BackpressureError(AuditPipeError):
    """投递队列已满，触发背压拒绝。"""


class ConfigError(AuditPipeError):
    """规则/管道配置错误。"""
