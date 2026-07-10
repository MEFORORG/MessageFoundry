A **Route** wires an inbound Connection to a Router, and the Router to one or more Handlers — there
is no bundled "channel" element, just named pieces wired together as a graph.

```python
@router("adt_router")
def route(msg):
    if msg["MSH-9.1"] != "ADT":
        return []  # routed nowhere -> logged UNROUTED
    return ["archive_handler"]


@handler("archive_handler")
def handle(msg):
    return Send("OB_ACME_ADT", msg)
```

The Route Wizard walks you through picking (or creating) the Connections, Router, and Handler.
