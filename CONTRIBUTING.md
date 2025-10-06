# Contributing

Thanks for your interest in improving `btsnoop-parser`! This project aims to stay
small and dependency-free, so please keep contributions lightweight and focused.

## Getting Started

1. Fork the repository on GitHub.
2. Clone your fork and create a feature branch.
3. Install the project in editable mode with the optional developer tools:
   ```bash
   pip install -e .[dev]
   ```
4. Run the test suite to ensure everything passes:
   ```bash
   python3 -m unittest discover -s tests
   ```

## Coding Guidelines

- Follow the existing code style and prefer explanatory variable names.
- Avoid introducing runtime dependencies unless absolutely necessary.
- Keep command-line output concise and informative.
- Add unit tests for new functionality or behavioural changes.
- Keep documentation (README, docstrings) aligned with any new features.

## Submitting Changes

1. Run the test suite and ensure it passes locally.
2. If adding CLI flags or API changes, update the README and docstrings.
3. Open a pull request against the `main` branch and fill in the template.
4. Be ready to discuss your approach and iterate during review.

## Reporting Issues

Use the GitHub issue tracker and include:

- The Python version and operating system.
- A minimal BTSnoop capture snippet if relevant.
- Steps to reproduce and the expected vs. actual behaviour.

Thank you for helping make `btsnoop-parser` better!
