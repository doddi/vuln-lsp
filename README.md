# Vulnerability Language Server Protocol

This is a simple language server for Sonatype vuln products.

Once built, ensure that the `vuln-lsp` binary is in your `$PATH`.

## Parameters

### Backend Service

The LSP can fetch data from either a `dummy` backend, [OssIndex](https://ossindex.sonatype.org/)
or a [Sonatype Lifecycle](https://www.sonatype.com/products/open-source-security-dependency-management)
`OssIndex` is the default setting.

### Logging

To enable logging add the parameter `--log-level=<Leve>` to the command line
arguments where `<level>` is any of the following:

- `error`
- `warn`
- `info`
- `debug`
- `trace`

### Transitive dependency scanning

By default the LSP will only scan the direct dependencies found in the project.
For a more thorough scan, run the LSP with the `-i` to include all the known
transitive dependency. This feature is currently experimental.

### Tracing

Tracing can be enable to either write to a file or using OpenTelemetry. The LSP
has to be built with either the `logging-file` or `logging-otel` feature.

## Limitations

At the moment the metadata scanning is basic and anything more than a typical
pom.xml (even dependency management is not working at the moment) will fail to
detect artifacts correctly.

## Editors

### Neovim

![neovim](./docs/vuln_vim.gif)

To enable the lsp for neovim, add the following to your `init.lua`:

```lua
vim.api.nvim_create_autocmd("bufenter", {
  pattern = { "pom.xml", "Cargo.toml" },
  callback = function()
    vim.lsp.start({
      name = "vuln-lsp",
      cmd = { "vuln-lsp" },
      root_dir = vim.fs.root(0, { "pom.xml", "Cargo.toml" }),
    })
  end,
})
```

This will start the lsp when you open either a `pom.xml` or `Cargo.toml` file.

### Vscode

![vscode](./docs/vuln_vscode.gif)

To build:

```bash
cd clients/vscode
npm install
```

To debug the lsp in vscode, first create a `launch.json` file in `.vscode/`
with the following contents:

```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "type": "extensionHost",
      "request": "launch",
      "name": "Debug LSP Extension",
      "runtimeExecutable": "${execPath}",
      "env": {
        "RUST_LOG": "debug"
      },
      "args": [
        "--extensionDevelopmentPath=${workspaceRoot}/anathema-lsp/clients/vscode",
        "--disable-extensions",
        "${workspaceRoot}/anathema-lsp/"
      ]
    }
  ]
}
```

Run the debugger and open the provided `test.anat` file to test the lsp.

### Intellij

![intellij](./docs/vuln_intellij.gif)

## Features

- Direct dependency scanning
- Optionally scan transitive dependencies
- Tracing support with OpenTelemetry
- Basic Maven support
- Basic Cargo support
