"""
DRF Adapter for Casbin

Ref:
  - https://github.com/casbin/pycasbin
"""

import abc

from rest_framework.permissions import BasePermission
import casbin


class BaseCasbinPermission(BasePermission, abc.ABC):
    def has_permission(self, request, view):
        e = casbin.Enforcer("path/to/model.conf", "path/to/policy.csv")
        sub = "alice"  # the user that wants to access a resource.
        obj = "data1"  # the resource that is going to be accessed.
        act = "read"  # the operation that the user performs on the resource.
        if e.enforce(sub, obj, act):
            return True
        else:
            # deny the request, show an error
            return False
