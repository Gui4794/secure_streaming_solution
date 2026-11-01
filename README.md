# Secure Streaming Solution

## Index
- [Context](#context)
- [Project Structure](#project-structure)
- [How to Compile and Run](#how-to-compile-and-run)

## Context
This assignment consists of a secure implementation of an streaming protocol: starting from the Java files written by our professor (Henrique Domingos), which concerned an insecure streaming solution, we were tasked with implementing security mechanisms and properties to make this a secure protocol, such as _(FILL WITH PROPERTIES)_. Together, we decided to build this project in Go, so we converted the given Java files to Go.

## Project Structure
_TODO: paste the project tree here once it is done_

As of right now, our project contains two key points of interest:
- the Stream Server, which hosts the file that the user wants to stream: it ciphers the file's blocks and securely sends it to the Proxy Server;
- the Proxy Server: the bridge between the Stream Server and the browser: it decrypts the blocks sent from the Stream Server and delivers them to the browser.



## How to Compile and Run
test3
