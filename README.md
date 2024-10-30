<div align="center">
<a href="https://agenticlabs.com/">
    <img src="https://raw.githubusercontent.com/agentic-labs/.github/main/assets/logo.png" alt="Agentic Labs" title="Agentic Labs" align="center" height="150px" />
</a>

# lsproxy - all your langauge servers are belong to us

<p align="center">
  <img alt="discord" src="https://img.shields.io/discord/1296271531994775552">
</p>
</div>


   
## <a name="what-is-lsproxy">What is lsproxy?</a>

`lsproxy` is a container with tools and an API for code analysis and navigation in large projects. 

It runs [Language Servers](https://microsoft.github.io/language-server-protocol/) and [ast-grep](https://github.com/ast-grep/ast-grep) to map relationships between code symbols (functions,  classes, variables) - which can be used to help AI assistants navigate code or build custom code RAG systems. 

All you have to do is mount your code.

## Key Features

- 🎯 **Precise Cross-File Code Navigation**: Find symbol definitions and references across your entire project.
- 🌐 **Unified API**: Access multiple language servers through a single API.
- 🛠️ **Auto-Configuration**: Automatically detect and configure language servers based on your project files.
- 📊 **Diagnostics**: (Coming Soon) Get project linter output from an endpoint.
- 🌳 **Call & Type Hierarchies**: (Coming Soon) Query multi-hop code relationships.
- 🔄 **Procedural Refactoring**: (Coming Soon) Perform symbol operations like `rename`, `extract`, `auto import` through the API.
- 🧩 **SDKs**: Libraries to get started calling `lsproxy` in popular languages.
    

## <a name="getting-started">Getting started</a>
The easiest way to get started is to run it yourself! We keep the latest version up to date on docker hub, and we have a python SDK available via `pip`. If you need additional inspiration for how this can be helpful to you, check out the [Examples](#examples) section.

### Install the sdk

You can find the documentation for the SDK [here](sdk.agenticlabs.com)
```bash
pip install lsproxy
```

### Run a container or add to compose
Make sure your `WORKSPACE_PATH` is an absolute path, otherwise docker will complain.
```bash
docker run -p 4444:4444 -v $WORKSPACE_PATH:/mnt/workspace agenticlabs/lsproxy
```

```dockerfile
services:
  lsproxy:
    image: agenticlabs/lsproxy
    ports:
      - "4444:4444"
    volumes:
      - ${WORKSPACE_PATH}:/mnt/workspace
```

### Explore your workspace!

```python
from lsproxy_sdk import Lsproxy

client = Lsproxy()
file_path = "relative/path/from/language/root.cpp"
symbols = client.file_symbols(file_path)
for symbol in symbols:
    print(f"{symbol.name} is defined in {file_path}")
```

## <a name="examples">Examples</a>
Most have you spin up a `lsproxy` docker container with your own code above and then just run the python script we provide, but we provide sample code for a few examples. See the README for each one for more info.

|Name|Description|Bring your own code?|
|:-|:-|:-|
|Playground|We've implemented a sample project in different languages and a UI built with [marimo](https://github.com/marimo-team/marimo) for you to play around with|**No**|
|Code Graph|Start from a single file and visualize how your code webs out|**Yes**|

## <a name="contributing">Contributing</a>

We appreciate all contributions! You don't need to be an expert to help out.
Please see [CONTRIBUTING.md](https://github.com/agentic-labs/lsproxy/blob/main/CONTRIBUTING.md) for more details on how to get
started.

> Questions? Reach out to us [on Discord](https://discord.gg/WafeS3jN).

## <a name="community">Community</a>

We're building a community. Come hang out with us!

- 🌟 [Star us on GitHub](https://github.com/agentic-labs/lsproxy)
- 💬 [Chat with us on Discord](https://discord.gg/WafeS3jN)
- ✏️ [Start a GitHub Discussion](https://github.com/agentic-labs/lsproxy/discussions)
- 🐦 [Follow us on Twitter](https://twitter.com/agentic_labs)
- 🕴️ [Follow us on LinkedIn](https://www.linkedin.com/company/agentic-labs)
  
## <a name="supported-languages">Supported languages</a>

We're constantly looking to add new language support or better language servers so let us know what you find!
|Language|Server|URL|
|:-|:-|:-|
|Javascript|`typescript-language-server`|https://github.com/typescript-language-server/typescript-language-server|
|Python|`pyright`|https://github.com/microsoft/pyright|
|Rust|`rust-analyzer`|https://github.com/rust-lang/rust-analyzer|
|Typescript|`typescript-language-server`|https://github.com/typescript-language-server/typescript-language-server|
|Your Favorite Language | Awesome Language Server | https://github.com/agentic-labs/lsproxy/issues/new |
