# External Plugins

Hardline can load additional plugins from a `plugins/` directory next to the binary.

The external plugin contract is:

- build as a Go shared object with `-buildmode=plugin`
- export a symbol named `HardlinePluginV1`
- the symbol type must be `*pluginapi.Plugin`

The repo contains an example external plugin project in:

```text
pluginprojects/firewalltemplate/
```

That example is built by `make build` into:

```text
tmp/plugins/firewall_template.so
```

Trust model:

- external plugins are not signature-verified
- they execute with root privileges through Hardline
- Hardline refuses to load them from a world-writable plugin directory
