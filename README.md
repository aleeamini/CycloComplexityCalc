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

![Image of Yaktocat](https://github.com/aleeamini/Function-Complexity-Plugin/blob/master/idacomplexity.PNG)


# Installation

First open up your binary file in IDA, then from File -> Script file, choose the CCC script. 
You can also try this with Alt+F7.

# Notes
CCC is tested and works perfectly on IDA Pro 7.0.
