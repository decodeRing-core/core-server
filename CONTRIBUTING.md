# Contributing to Open Secret Language (OSL)

Thank you for your interest in contributing!

This project aims to define a lightweight, practical, open standard for how developers and security engineers talk about cybersecurity secrets. Contributions of all kinds are welcome: feedback, clarifications, examples, and new ideas.

> If you fork this template for another project, replace “Open Secret Language (OSL)” and update links as needed.

---

## 1. Ways You Can Contribute

You don’t have to write a lot to be helpful. Examples:

- **Give feedback** on terminology, definitions, or examples.
- **Propose changes** to the standard (clarifications, new sections, better wording).
- **Add examples** (architecture docs, incident report snippets, metadata examples).
- **Improve documentation** (README, structure, formatting).
- **Open issues** describing real-world problems this standard should address.

If you’re unsure whether an idea fits, open an issue and start a conversation.

---

## 2. Ground Rules

By participating in this project, you agree to:

- Be respectful and constructive in discussions.
- Assume good faith and seek clarity before escalating disagreements.
- Keep the focus on improving the standard for developers and security engineers.

If this repository includes a `CODE_OF_CONDUCT.md`, please read and follow it.

---

## 3. Before You Start

1. **Check existing issues and PRs**  
   Someone may already be working on a similar change. Comment there instead of starting a duplicate thread.

2. **Open an issue for non-trivial changes**  
   For anything that:
   - Introduces new terminology,
   - Changes definitions,
   - Adds or modifies lifecycle states or metadata fields,
   please open an issue first so we can discuss the design.

3. **Keep it practical**  
   This project targets real-world use by developers and security engineers. When proposing changes, include:
   - A short motivation: what problem is this solving?
   - A concrete example from practice, if possible.

---

## 4. How to Propose Changes

### 4.1. Small Changes (Typos, Minor Clarifications)

1. Fork the repo.
2. Create a branch (e.g. `docs/fix-typo-in-lifecycle`).
3. Make your edits.
4. Open a Pull Request with:
   - A clear title.
   - A short description of what you changed and why.

These can usually be merged quickly.

### 4.2. Larger Changes (New Terms, Lifecycle, Metadata, Structure)

1. **Open an issue first** describing:
   - The proposed change.
   - Why it’s needed.
   - Any alternatives you considered.
2. Discuss and refine the idea in the issue.
3. Fork the repo and implement the agreed change in a branch (e.g. `spec/add-derived-secret-definition`).
4. Open a Pull Request:
   - Reference the issue (`Closes #123`).
   - Clearly explain the impact (e.g. “adds a new term”, “renames lifecycle state”, “adds new metadata field”).

For changes that affect the core model or terminology, please include at least one **worked example** showing how it would be used in practice.

---

## 5. Style Guidelines

This project is mostly text (Markdown) and simple examples. Please follow these guidelines when editing:

### 5.1. Markdown

- Use `#`, `##`, `###` headings consistently.
- Prefer short paragraphs and bullet lists for readability.
- Use backticks for code/identifiers: `secret`, `credential`, JSON keys, etc.
- Wrap lines at a reasonable length (e.g. 80–100 chars) where practical.

### 5.2. Terminology

- Use the project’s defined terms consistently: **secret**, **credential**, **key**, **token**, **configuration secret**, **derived secret**, etc.
- If you introduce a new term:
  - Define it clearly.
  - Explain how it relates to existing terms (is it a subtype, alternative name, etc.?).
  - Add it to the appropriate definitions section.

### 5.3. Examples

- Use realistic but non-sensitive values (no real secrets, keys, or tokens).
- Prefer JSON or YAML for machine-readable examples, and clear prose for narrative examples.
- When possible, show:
  - The **`id`**, **`type`**, **`owner`**, **`scope`**, and **`protection_level`** for secret descriptors.
  - Lifecycle states and events in incident report examples.

---

## 6. Pull Request Checklist

Before opening a PR, please:

- [ ] Confirm your changes build or render correctly (Markdown is valid, examples are well-formed).
- [ ] Update or add examples if your change affects how the standard should be used.
- [ ] Update any relevant references (e.g. table of contents, cross-links).
- [ ] Briefly explain _why_ the change is needed, not just _what_ it is.

---

## 7. Licensing and Legal

This project is licensed under the **Apache License, Version 2.0**.

By submitting a contribution (issue, pull request, or other content), you agree that:

1. **License of Contributions**  
   You grant the project maintainers and users a license to use your contributions under the terms of the Apache License 2.0, as if they were part of the original project.

2. **Right to Contribute**  
   You represent that you have the necessary rights to submit the contribution and that you are not knowingly violating any third-party rights.

3. **Third-Party Content**  
   If your contribution includes or depends on third-party content, you must clearly identify it and ensure it is compatible with the Apache License 2.0.

The full license text can be found in the `LICENSE` file at the root of the repository.

---

## 8. Getting Help

If you’re not sure where to start:

- Look at existing issues labeled `good first issue` or `help wanted` (if present).
- Open an issue with the label `question` describing what you’d like to do.

Thanks again for helping improve Open Secret Language (OSL)!
