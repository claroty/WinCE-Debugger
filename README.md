# WinCE-Debugger

**WinCE-Debugger** is a Python-based utility designed to assist researchers in debugging and dynamically analyzing applications running on **Windows CE**. With a modular architecture and intuitive UI powered by modern Python libraries, it provides a streamlined workflow for runtime application inspection.

## 🚀 Features

- Background debugger service for Windows CE targets  
- Debugger client interface with rich, responsive UI  
- Support for dynamic binary analysis via [angr](https://github.com/angr/angr)  
- Disassembly, memory inspection, and more with [Capstone](http://www.capstone-engine.org/)


## 🛠 Requirements

Make sure you have Python 3.8+ installed. Then install the required dependencies:

```bash
pip install rich angr textual capstone construct nest_asyncio
```


## 📦 Installation

Clone this repository and navigate into it:

```bash
git clone https://github.com/claroty/WinCE-Debugger.git 
cd WinCE-Debugger
```


Install the dependencies as shown above, and you're ready to go.

## ⚙️ Usage

1. **Start the Debug Service**

   Launch the background debugger connection service to listen for incoming connections from a Windows CE device or emulator.

```bash
python debug_service.py
```


2. **Start the Debugger Client**

Run the debugger interface to interact with the target system:

```bash
python debugger_client.py
```


3. **Connect & Analyze**

Once connected, you'll be able to inspect memory, analyze control flow, and explore the application state in real-time.

## 🧠 Powered By

- [angr](https://github.com/angr/angr) – Binary analysis platform  
- [Capstone](http://www.capstone-engine.org/) – Lightweight multi-architecture disassembly framework  
- [Textual](https://github.com/Textualize/textual) & [Rich](https://github.com/Textualize/rich) – TUI for Python  
- [Construct](https://github.com/construct/construct) – Declarative binary data parser  
- [nest_asyncio](https://github.com/erdewit/nest_asyncio) – Async support for nested event loops

## 🪪 License

This project is **open source**. See [LICENSE](./LICENSE) for more details.
