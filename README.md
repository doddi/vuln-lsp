# IQ Language Server Protocol

This is a simple language server for Sonatype IQ products.

Once built, ensure that the `iq-lsp` binary is in your `$PATH`.

## Editors

### Neovim

To enable the lsp for neovim, add the following to your `init.lua`:

```lua
vim.api.nvim_create_autocmd("BufEnter", {
  pattern = "pom.xml",
  callback = function()
    vim.lsp.start({
      name = "iq-lsp",
      cmd = { "iq-lsp" },
      root_dir = vim.fs.dirname(vim.fs.find({ "pom.xml" }, { upward = true })[1]),
    })
  end,
})
```

This will start the lsp when you open a  `pom.xml`  file.

### Vscode

To build:

```bash
cd clients/vscode
npm install
```

To debug the lsp in vscode, first create a `launch.json` file in `.vscode/`
with the following contents:

```json
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

## Features

