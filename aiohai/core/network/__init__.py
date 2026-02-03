"""
Network Security — Socket-level interception.

Classes:
- NetworkInterceptor: Hooks socket.connect/getaddrinfo/gethostbyname,
                      blocks private IPs, DoH servers, DNS tunneling
"""

from aiohai.core.network.interceptor import NetworkInterceptor

__all__ = ['NetworkInterceptor']
