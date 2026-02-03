#!/usr/bin/env python3
"""Home Assistant Notification Bridge - Forward alerts to HA dashboard."""
import logging
logger = logging.getLogger("aiohai.integrations.smart_home")

try:
    from security.security_components import HomeAssistantNotificationBridge
except ImportError:
    class HomeAssistantNotificationBridge:
        def __init__(self, config): raise ImportError("Requires security_components")

__all__ = ['HomeAssistantNotificationBridge']
