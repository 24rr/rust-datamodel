# Roblox Datamodel Dumper

![image](assets/image.png)

## Method Used

- String-based scanning for DataModel-related identifiers
- Scene/Rendering object detection to find RenderView objects which point to the DataModel
- Workspace object scanning to find instances that are children of the DataModel

When any strategy successfully locates a potential address, the program validates it by checking memory structure patterns and following pointer chains with specific offsets. Once validated, it traverses the memory hierarchy using predefined offsets to map out the complete DataModel structure and its child components. This multi-layered approach ensures robustness against Roblox updates by not relying on a single detection method.