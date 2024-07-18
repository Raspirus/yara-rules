# Raspirus YARA Collection

Welcome to the Raspirus Project's collection of YARA rules. This repository hosts a curated set of YARA rules designed to enhance malware detection and analysis capabilities.

## Structure

- **rules/**: Contains all the YARA rules, organized by vendor. Each vendor has its own folder, and the rules within these folders include a name and a short description.
- **scripts/**: A collection of Python scripts for manipulating the rules. One key script creates a binary release of the rules, which is uploaded as a release and used as the Raspirus database.

## Adding Your Own Rules

Contributions are highly encouraged! To add your own rules:

1. **Fork the repository** and create a new branch.
2. **Add your rule** to the appropriate vendor folder in the `rules` directory. If necessary, create a new folder for your vendor.
3. **Submit a Pull Request (PR)** with a brief description of the rule you're adding.
4. You can also improve or modify existing rules by following the same process.

If you encounter any issues with a rule, please open an issue, specifying the file or rule name. We will investigate and address the issue as soon as possible.

## Sources
- [YARA HQ](https://yarahq.github.io)
- [Yara-Rules GitHub Repository](https://github.com/Yara-Rules/rules)

We appreciate your contributions and support in making the Raspirus YARA collection a valuable resource for the community!
