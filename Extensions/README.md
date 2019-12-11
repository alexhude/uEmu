## uEmu extension system

It is possible to add new functionality or build your project on top of **uEmu** using extension system.  

### Overview

There are several simple steps to implement **uEmu** extension.  

1. Inherit from **uEmu** plugin class `class MyEmuPlugin(uEmuPlugin)`
2. Override plugin functions to add menu, update context and close windows if needed
3. Fill and pass `uEmuExtensionHooks` structure back to **uEmu** `__init__()`
4. Put extension in the same folder next to the `uEmu.py`

### Plugin methods

In order to inject new code into plugin workflow you should override following methods:

#### add\_custom\_menu(self)

Add your own menu items by calling `self.MENU_ITEMS.append(UEMU_HELPERS.MenuItem(...))`.
`UEMU_HELPERS.MenuItem` has following input agruments:

```
action,   # IDA action identifier (ex. MyEmu:myemu_test) or '-' for separator
handler,  # function called when menu item is clicked
title,    # menu item name
tooltip,  # menu item tooltip
shortcut, # menu item shortcut
is_popup  # set to True if item should be added to popup menu, False otherwise
```

It is also a good practice to finish extension menu block with separator.

```
self.MENU_ITEMS.append(UEMU_HELPERS.MenuItem("-", self.do_nothing, "", None, None, True))
```

#### update\_context(self, address, context)

This method is called every time CPU context (registers, stack, memory) has changed. All custom context views need to be updated here.

#### close\_windows(self)

Use this method to release/destroy your objects and views when **uEmu** is closing/resetting.

### Engine Hooks

Followig hooks allow to inject code into **uEmu** emulation engine.

They are defined in `uEmuExtensionHooks` structure which should be passed to `uEmuPlugin`.

```
def __init__(self):
    hooks = uEmuExtensionHooks()
    hooks.init_context = self.hook_init_context
    hooks.trace_log = self.hook_trace_log
    hooks.emu_step = self.hook_emu_step
    super(MyEmuPlugin, self).__init__("MyEmu", hooks)
```

**NOTE: hooks are not necessarily called on IDA main thread.**  
Use `UEMU_HELPERS.exec_on_main(handler, flag)` to execute your code on main thread

#### hook\_init\_context(self)

Current hook makes it possible to init CPU context in extension and bypass **uEmu** default dialogs.  
Return `False` from this function to let **uEmu** init context, `True` otherwise.

#### hook\_trace\_log(self, pc)

When `Trace instruction` option is set this hook will be called to output new log entry.  
Return `False` from this function to let **uEmu** output its own trace log, `True` otherwise.

#### hook\_emu\_step(self, pc)

Use this method to perform extra actions during **uEmu** emulation.  
Return `False` from this function to let **uEmu** execute instruction, `True` otherwise.

### Examples

Please find **MyEmu** extention example [here](./MyEmu.py)


