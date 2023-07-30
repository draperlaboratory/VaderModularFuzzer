# Contributing to VMF

Thank you for your interest in contributing to VMF! The following is a set of guidelines for contributing to VMF and its associated modules, which are hosted on this site.

## Legal Requirements

In order to become a contributor, you first need to sign the appropriate [Contributor License Agreement](vmf_contributor_license_agreement.pdf).

## Code of Conduct

This project and everyone participating in it is governed by the [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to [vmf@draper.com](mailto:vmf@draper.com).


## Overview

VMF is an open-source project. If you are interested in making it better, there are many ways you can contribute. For example, you can:

- Submit a bug report
- Propose a bug fix by submitting a pull request
- Suggest new module or feature
- Propose a new module by submitting a pull request
- Suggest or submit documentation improvements
- Answer questions from other users
- Share the software with other users who are interested
- Teach others to use the software

## Submitting Bugs and Feature Requests

If you believe that you have found a bug or wish to propose a new feature, please first search the existing [issues] to see if it has already been reported. If you are unable to find an existing issue, consider using one of the provided templates to create a new issue and provide as many details as you can to assist in reproducing the bug or explaining your proposed feature.

## Contribution Submission Guidelines

Generally, any issue that doesn't have an Assignee is free for anyone to work on.  Assign the issue to yourself to indicate you intend to start working on it shortly.  Please unassign yourself if you no longer have time work on it so that someone else may pick it up.

Treat the issue as a place to document decisions about the issue, hold discussions in the comments, create to-do lists, paste diagrams, or whatever you think would be helpful for you during development.  Try to keep the description up to date as development progresses.

Contributions should be submitted in the form of Pull Requests to the VMF [repository] on GitHub.

### Repo Structure and Hygiene
Our code repo follows the "OneFlow" pattern described [here]( https://www.endoflineblog.com/implementing-oneflow-on-github-bitbucket-and-gitlab). As the name suggests, there is a single persistent "main" branch. Other branches are all temporary and are deleted once the changes have been merged back into main. Releases are marked (and created) via git tags.

#### Release Readiness
Our current criteria for release readiness is that all unit tests pass, and sign-off obtained from a majority of the official maintainers.

#### Mergeability
When making a PR, it helps to try to keep it mergeable into the official repo. In practice, this usually means periodically rebasing on main when there are changes upstream after your PR was created.

### Code Standards
For a smooth code review, it helps to make sure your code adheres to standards, conventions, and design goals for VMF. A best-effort attempt to understand and meet these standards before requesting code review can go a long way towards making the review process as fast and painless as possible.

### Other Information and Tips

Please consider the following tips to ensure a smooth process when submitting:

- Ensure that the code compiles and does not break any build-time tests.
- Be understanding, patient, and friendly; the VMF team needs time to review your submission before they can act or respond. This does not mean your contribution is not valued. If your contribution has not received a response in a reasonable time, consider commenting with a polite inquiry for an update.
- Limit individual changes to the smallest reasonable change to achieve your intended goal. For example, do not make unnecessary indentation changes; but don't go out of your way to make the patch so minimal that it isn't easy to read, either. Consider the reviewer's perspective.
- Isolate multiple patches from each other. If you wish to make several independent patches, do so in separate, smaller pull requests that can be reviewed more easily.
- Before submission, please squash your commits and use a message that starts with the issue number and a description of the changes. We suggest following the “[seven rules of a great Git commit message]( https://cbea.ms/git-commit/).”
- Be prepared to answer questions from reviewers. They may have further questions before accepting your patch and may even propose changes. Please accept this feedback constructively, and not as a rejection of your proposed change.
- Unless previously authorized by the VMF team, repackaging, renaming, and other refactoring should not be part of any pull request. These types of changes are difficult to review, pollute the git history making it harder to do git forensics on regressions, and will likely conflict with other changes that the VMF team is making internally.
- Avoid "find and replace" changes in your pull request. While it may be tempting to globally replace calls to deprecated methods or change the style of the code to fit your personal preference, these types of seemingly trivial changes have likely not already been performed by the VMF team for good reason.
- Please do not submit pull requests that update 3rd party dependencies. It is preferred that these changes are made internally by the team. If you have a need for an updated tool or library, please submit an issue with your request instead of a pull request.

## Legal

Consistent with Section D.6. of the GitHub Terms of Service as of 2022, the project maintainer for this project accepts contributions using the inbound=outbound model. When you submit a pull request to this repository (inbound), you are agreeing to license your contribution under the same terms as specified in [LICENSE] (outbound).
