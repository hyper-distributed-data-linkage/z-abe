# Contributing

Thank you for your interest in contributing to this project.

## Developer Certificate of Origin

This project requires all commits to be signed off under the [Developer Certificate of Origin](https://developercertificate.org) (DCO). Signing off certifies that you have the right to submit the contribution under this project's license.

To sign off a commit, use the `-s` option:

```bash
git commit -s -m "Your commit message"
```

This adds a `Signed-off-by` line using your Git author identity. Every commit in a pull request must include one.

If a commit is missing its sign-off, amend it and re-push:

```bash
git commit --amend -s --no-edit
git push --force-with-lease
```

## Pull request requirements

Before opening a pull request, please make sure that:

* Your commits are signed off and the DCO check passes.
* The pull request clearly describes the change.
* Tests and checks pass, where applicable.
