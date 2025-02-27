# Library Internals

This document describes the internals of the library. It is intended for developers who want to contribute to the library.


## pyquickshare

This fully documents the `pyquickshare` module. Including private members.

```{eval-rst}
.. automodule:: pyquickshare
   :members:
   :show-inheritance:
   :undoc-members:
   :private-members:
   :ignore-module-all:
   :no-index:
```



## firewalld

```{eval-rst}
.. automodule:: pyquickshare.firewalld
   :members:
   :show-inheritance:
   :undoc-members:
   :ignore-module-all:
```


## ukey2

For some reason, Sphinx cannot seem to resolve some of the typehints from the protobuf generated code.
That's why some typehints may look odd.

```{eval-rst}
.. automodule:: pyquickshare.ukey2
   :members:
   :show-inheritance:
   :undoc-members:
   :ignore-module-all:
```

## mdns

The `mdns` module provides an interface to the mDNS implementation on the system.
It also handles BLE advertisement.
Communication with the mDNS implementation and BlueZ is done via D-Bus.

```{eval-rst}
.. automodule:: pyquickshare.mdns.send
   :members:
   :show-inheritance:
   :undoc-members:
   :ignore-module-all:
```

```{eval-rst}
.. automodule:: pyquickshare.mdns.receive
   :members:
   :show-inheritance:
   :undoc-members:
   :ignore-module-all:
```

## common

```{eval-rst}
.. automodule:: pyquickshare.common
   :members:
   :show-inheritance:
   :undoc-members:
   :ignore-module-all:
```