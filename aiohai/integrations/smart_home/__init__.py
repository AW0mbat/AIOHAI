"""
Smart Home Integration — Home Assistant + Frigate.

Classes:
- LocalServiceRegistry: Allowlist of queryable local services
- LocalAPIQueryExecutor: Execute queries with PII protection
- SmartHomeConfigAnalyzer: Validate HA/Frigate YAML configs
- SmartHomeStackDetector: Auto-discover Docker-based smart home stack
- HomeAssistantNotificationBridge: Forward alerts to HA dashboard
"""

from aiohai.integrations.smart_home.service_registry import LocalServiceRegistry
from aiohai.integrations.smart_home.query_executor import LocalAPIQueryExecutor
from aiohai.integrations.smart_home.config_analyzer import SmartHomeConfigAnalyzer
from aiohai.integrations.smart_home.stack_detector import SmartHomeStackDetector
from aiohai.integrations.smart_home.notification import HomeAssistantNotificationBridge

__all__ = [
    'LocalServiceRegistry',
    'LocalAPIQueryExecutor', 
    'SmartHomeConfigAnalyzer',
    'SmartHomeStackDetector',
    'HomeAssistantNotificationBridge',
]
