# Counterfeit Object Oriented Programming (COOP)

## Abstract

The main idea behind COOP is counterfeiting – that is crafting new objects in-memory from attacker-controlled payloads and to chain them together through virtual functions that are already present in the target application or in loaded libraries.
Each virtual function contained in a counterfeit object is called a vfgadget and is responsible for performing a small task. Similarly to ROP, vfgadgets can perform tasks like populating a value into a register. However when grouped together, multiple vfgadgets can execute more advanced operations, like API invokation.

More information about COOP technique can be found [here](https://www.matteomalvica.com/blog/2022/09/22/bypassing-intel-cet-counterfeit-objects)

## Contents

This repository contains the following material:

* **COOP_PoC**: A proof-of-concept application that demonstrates  Counterfeit_Object_Oriented_Programming
* **CVE-2019-0539_COOP**: Exploit for CVE-2019-0539 based on COOP gadgets.
* **COOP.pdf**: Presentation slide deck
* **demos**: a few demo videos of the PoC application and the MS Edge CVE


## Demos



[PoC - Triggering Shadow Stack](https://github.com/uf0o/Counterfeit_Object_Oriented_Programming_COOP/assets/24236867/c0a6faeb-a336-44db-86e0-da95f42cc5d9)

[PoC- Invoke vfgadget that triggers WinExec](https://github.com/uf0o/Counterfeit_Object_Oriented_Programming_COOP/blob/main/demos/poc1.mov)

[CVE-2019-0539](https://github.com/uf0o/Counterfeit_Object_Oriented_Programming_COOP/assets/24236867/ad169d3a-1a03-4b99-ae58-6d200586e5b8)



