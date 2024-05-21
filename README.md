This is a very simple Python script that extracts icons from an exe file.

Usage:
```
python main.py foo.exe
```

Why not use Resource Hacker?

[Resource Hacker](https://www.angusj.com/resourcehacker/) is a very famous software for modifying and extracting resources from PE files. Of course, we can use it to extract icons. But Resource Hacker is not an open-source software, and I found that the header of the icon files extracted using Resource Hacker had problems, which caused the images to not display properly in certain environments, so I decided to reinvent the wheel.

References:
1. https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
2. https://learn.microsoft.com/en-us/previous-versions/ms809762(v=msdn.10)#pe-file-resources
3. https://devblogs.microsoft.com/oldnewthing/20120720-00/?p=7083
4. https://learn.microsoft.com/en-us/windows/win32/menurc/resource-types
5. https://en.wikipedia.org/wiki/ICO_(file_format)

