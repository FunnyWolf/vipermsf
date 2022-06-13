Maintainers can assign labels to both issues and pull requests.

### Docs

Documentation changes, such as YARD markup, or README.md, or something along those lines.

### External

Touches something in /external, or the Gemfile, or something like that.

### Heartbleed

Has to do with heartbleed. This will go away soon, but there are three outstanding still...

### Library

Touches something in /lib.

### Meterpreter

Has to do with Meterpreter, or depends on a Meterpreter change to land to work.

### Misc

Plugins and scripts, anything that's not otherwise defined.

### Module

Touches something in /modules

### Specs

Has specs (an rspec test)

### Newbie Friendly

Something that's pretty easy to test or tackle.

### attic

When we move something to the attic it means that what you submitted is a thing that we want but the circumstances were not quite right for landing it. Sometimes this is on us, and sometimes the contribution needs more work. We recognize that contributors work on the PRs they submit at their own pace. Take a look at the comments and review suggestions on your PR, and feel free to re-open it if and when you have time to work on it again. Don't think you'll be able to get it across the finish line? Find a community champion to do it for you.

### Needs unique branch

Your submitted a PR from your `master` branch.

Because of how GitHub tracks changes between branches and what got added in a particular PR, we don't accept contributions from the `master` branch of your fork. All branches are [required to be unique](https://github.com/rapid7/metasploit-framework/blob/master/CONTRIBUTING.md#code-contributions). If your PR is closed because of this, create a new branch with that code and we'll be happy to look at it again!
```
git checkout -b <BRANCH_NAME>
git push <your_fork_remote> <BRANCH_NAME>
```
This helps protect the process, ensure users are aware of commits on the branch being considered for merge, allows for a location for more commits to be offered without mingling with other contributor changes and allows contributors to make progress while a PR is still being reviewed.