<!--
⚠️ NO AI SLOP!!!
⚠️ If you didn't do manual QA and testing on this PR you shouldn't be PRing
-->

# Summary

In this pull request, the following changes are made:

- Foobar was changed to FooFoo, because ...

<!--Please link any GitHub issues or tasks that this pull request addresses-->

- Relates to #issue-number <!--this links the related issue-->
- Resolves #issue-number <!--this auto-closes the issue-->

<details>
<summary>Please follow this checklist to avoid unnecessary back and forth (click to expand)</summary>

- [ ] 🧠 I used LLMs/AI in this contribution and reviewed all generated content.
      I understand that I am responsible for and able to explain every line of code I submit.
- [ ] 🛠️ I have self-reviewed my code and self-tested it against a MeshCentral server to ensure it works as expected.
- [ ] 🖥️ My change compiles on every platform it affects (Windows / Linux / macOS / FreeBSD), and I have considered
      the impact on platforms and architectures I could not test.
- [ ] 📦 If I changed JavaScript modules under `modules/`, I re-embedded them so the compiled-in copies in
      `microscript/ILibDuktape_Polyfills.c` match (the agent runs the embedded copies, not the files on disk).
- [ ] 🤖 I ran the agent self-test where appropriate (see "Self Test" in [readme.md](../readme.md)).
- [ ] 📄 Documentation updates are included (if applicable), e.g. the `.msh` options table in [readme.md](../readme.md).
- [ ] 🧰 Updates to vendored dependencies (OpenSSL, zlib, ...) are listed and explained.
- [ ] ⚠️ CI passes and is green (Windows / Linux / macOS / FreeBSD builds and CodeQL).

</details>

## Testing

<!--
Describe how you tested this change: which platforms/architectures you ran the agent on,
and the MeshCentral server version you tested against.
-->

| Platform (OS / distro / arch) | Tested | Result |
| ----------------------------- | ------ | ------ |
| e.g. Windows 11 x64           | ✅     |        |
| e.g. Debian 13 x64 (Wayland)  | ✅     |        |

## Screenshots for Visual Changes

<!--
If this pull request changes anything with a visual outcome (remote desktop/KVM, terminal,
file transfer, installer dialogs), please include before & after screenshots.
If not, remove this section.

Please upload the image directly here by pasting it or dragging and dropping.
-->

| Event | Before                | After                |
| ----- | --------------------- | -------------------- |
|       | ![Before](image-link) | ![After](image-link) |
