# CycloComplexityCalc (CCC Plugin)

CycloComplexityCalc is an IDAPython module designed to extract some useful characteristics from binary functions and then calculate the complexity of each function. 
It does that in order to help our fuzzers dig into their targets precisely. 
It's also quite practical for malware analysis since complex functions are generally being used in cryptographic tasks, memory interactions, and so on.

CCC counts and calculates:

* BasicBlocks of each function
* Loops and Nested-Loops of each function (Tarjan's Algorithm)
* JumpTables and SwitchCases of each function
* Pointers of each function
* Maximum input edges to a block of each function
* A cyclomatic criteria

In a sorted and visualized manner. CCC is designed as an IDA tab.

![Image of Yaktocat](https://github.com/aleeamini/CycloComplexityCalc/blob/master/ccc.PNG)


# Installation

First open up your binary file in IDA, then from File -> Script file, choose the CCC script. 
You can also try this with Alt+F7.

# Notes
CCC is tested and works perfectly on IDA Pro 7.0.

There's another tool called IDAMetrics-static.py which is typically different from the CCC:
CCC's metrics are basically more sophisticated (e.g. loops, pointers & switch cases), which are implemented through the Tarjan's algorithm that the so-called tool lacks.
These are the main metrics that impact the runtime analysis. 
CCC's fundamentally based on security metrics, while the IDAMetrics-static tool is rooted in software development metrics.
